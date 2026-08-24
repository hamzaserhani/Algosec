"""
Pre-check des flux : interroge AlgoSec AFA (traffic simulation query) pour savoir
si un flux est DEJA autorise sur les firewalls, AVANT de creer une demande FireFlow.

Pour chaque demande du fichier :
    1. Reconstruit le flux (memes sources/dest/services que la creation).
    2. Lance une AFA traffic query (auto-path sur tout le reseau).
    3. Classe le resultat : ALLOWED / BLOCKED / PARTIAL / NOT_ROUTED / ERROR.
    4. Ecrit une colonne 'deja_autorise' dans le fichier (+ rapport).

Principe de securite : seul un flux ENTIEREMENT 'allowed' est marque ALLOWED
(=> saut de la creation). Tout le reste -> on cree le ticket (defaut sur).

Usage:
    python check_flows.py demandes_clean.csv
    python check_flows.py demandes_clean.csv --only 244 --raw   # calibration : dump brut
    python check_flows.py demandes_clean.csv --json rapport_flux.json
"""

import argparse
import csv
import json

from afa_client import AfaClient
from bulk_create_requests import (
    load_requests,
    row_to_ticket,
    apply_source_object_map,
    read_csv_rows,
    read_xlsx_rows,
    _norm,
)

# Valeurs de statut connues renvoyees par AFA (normalisees)
STATUS_ALIASES = {
    "allowed": "ALLOWED",
    "blocked": "BLOCKED",
    "partially allowed": "PARTIAL",
    "partially blocked": "PARTIAL",
    "not routed": "NOT_ROUTED",
    "unreachable": "NOT_ROUTED",
}

# Cles de la reponse susceptibles de porter le verdict
VERDICT_KEYS = ("queryresult", "result", "action", "isallowed", "trafficallowed")


def _collect_verdicts(node, found):
    """Collecte recursivement les valeurs de statut trouvees dans la reponse."""
    if isinstance(node, dict):
        for k, v in node.items():
            if _norm(k).replace(" ", "") in VERDICT_KEYS and isinstance(v, str):
                found.append(v.strip().lower())
            _collect_verdicts(v, found)
    elif isinstance(node, list):
        for item in node:
            _collect_verdicts(item, found)


def classify_result(result):
    """Classe la reponse AFA. Retourne (statut, verdicts_bruts)."""
    found = []
    _collect_verdicts(result.get("data", result) if isinstance(result, dict) else result, found)

    # Normalise chaque verdict. IMPORTANT: tester les alias les plus longs
    # d'abord ('partially allowed' avant 'allowed', sinon faux ALLOWED).
    norm = set()
    aliases_by_len = sorted(STATUS_ALIASES.items(), key=lambda kv: -len(kv[0]))
    for v in found:
        for alias, canon in aliases_by_len:
            if alias in v:
                norm.add(canon)
                break
        else:
            if v == "true":
                norm.add("ALLOWED")
            elif v == "false":
                norm.add("BLOCKED")

    if not norm:
        return "UNKNOWN", found
    # Conservateur : ALLOWED seulement si TOUT est allowed (aucun autre etat)
    if norm == {"ALLOWED"}:
        return "ALLOWED", found
    if "BLOCKED" in norm and "ALLOWED" in norm:
        return "PARTIAL", found
    if "PARTIAL" in norm:
        return "PARTIAL", found
    if "BLOCKED" in norm:
        return "BLOCKED", found
    if "NOT_ROUTED" in norm:
        return "NOT_ROUTED", found
    return "UNKNOWN", found


def afa_service(svc):
    """Convertit un service interne ('tcp/443','udp/53','any') au format AFA."""
    if not svc or svc.lower() == "any":
        return "any"
    return svc  # AFA accepte 'tcp/443' ; on ajustera si besoin


def read_source_rows(path):
    import os
    ext = os.path.splitext(path)[1].lower()
    return read_xlsx_rows(path) if ext == ".xlsx" else read_csv_rows(path)


def write_column(input_path, results_by_id):
    """Ecrit la colonne 'deja_autorise' dans le fichier (par '#')."""
    import os
    ext = os.path.splitext(input_path)[1].lower()
    out_path = input_path if ext != ".xlsx" else os.path.splitext(input_path)[0] + "_flux.csv"
    raw = read_source_rows(input_path)
    if not raw:
        return
    headers = list(raw[0].keys())
    id_key = next((h for h in headers if _norm(h) == "#"), None)
    if id_key is None:
        print("[WARN] Colonne '#' introuvable : colonne deja_autorise non ecrite.")
        return
    fieldnames = headers + (["deja_autorise"] if "deja_autorise" not in headers else [])
    for row in raw:
        rid = (row.get(id_key) or "").strip()
        row["deja_autorise"] = results_by_id.get(rid, row.get("deja_autorise", ""))
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(raw)
    print(f"[OK] Colonne 'deja_autorise' ecrite dans {out_path}.")


def main():
    parser = argparse.ArgumentParser(description="Pre-check des flux via AFA traffic query")
    parser.add_argument("input_file", help="Fichier de demandes (.csv ou .xlsx)")
    parser.add_argument("--config", default="config.json", help="Fichier de config")
    parser.add_argument("--only", help="Ne tester que ces '#' (liste separee par virgules)")
    parser.add_argument("--raw", action="store_true", help="Affiche la reponse AFA brute (calibration)")
    parser.add_argument("--json", dest="json_path", help="Sauve le rapport detaille en JSON")
    parser.add_argument("--no-write", action="store_true", help="Ne pas ecrire la colonne deja_autorise")

    args = parser.parse_args()

    only_ids = {x.strip() for x in args.only.split(",")} if args.only else None

    rows = load_requests(args.input_file)
    flows = []
    for row in rows:
        ticket, _ = row_to_ticket(row)
        if ticket is None:
            continue
        if only_ids is not None and (ticket.get("id") or "").strip() not in only_ids:
            continue
        apply_source_object_map(ticket, {})  # sources telles quelles (map applique a la creation)
        flows.append(ticket)

    if not flows:
        print("[INFO] Aucun flux a tester.")
        return

    print(f"[INFO] {len(flows)} flux a tester via AFA.")
    client = AfaClient(args.config)
    client.login()

    results_by_id = {}
    reports = []
    counts = {}
    for i, t in enumerate(flows, start=1):
        rid = t.get("id") or "?"
        services = [afa_service(s) for s in t["services"]]
        print(f"\n--- Flux {i}/{len(flows)} (#{rid}) ---")
        print(f"  src={t['sources']} dst={t['destinations']} svc={services}")
        try:
            result = client.query(t["sources"], t["destinations"], services)
        except Exception as e:
            full = str(e)
            # Affiche le corps complet de l'erreur (diagnostic du 400 AFA)
            print(f"  [ERREUR] {full[:1200]}")
            results_by_id[rid] = "ERROR"
            counts["ERROR"] = counts.get("ERROR", 0) + 1
            reports.append({"id": rid, "status": "ERROR", "error": full[:1200]})
            continue

        if args.raw:
            print(json.dumps(result, indent=2, ensure_ascii=False))

        status, verdicts = classify_result(result)
        print(f"  => {status}  (verdicts bruts: {verdicts or 'aucun'})")
        results_by_id[rid] = status
        counts[status] = counts.get(status, 0) + 1
        reports.append({"id": rid, "status": status, "verdicts": verdicts,
                        "sources": t["sources"], "destinations": t["destinations"],
                        "services": services})

    print(f"\n{'='*40}")
    print("Resume:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    allowed = counts.get("ALLOWED", 0)
    print(f"-> {allowed} flux DEJA AUTORISE(S) (ticket evitable), "
          f"{len(flows) - allowed} a creer.")

    if not args.no_write and not args.raw:
        write_column(args.input_file, results_by_id)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport detaille -> {args.json_path}")


if __name__ == "__main__":
    main()

"""
Pre-check INFORMATIF des flux via le moteur de policy (evaluation statique).

Pour chaque flux, evalue s'il est deja autorise par la POLICY des firewalls
configures (config.json 'policy_firewalls'). Ecrit une colonne 'policy' A TITRE
INDICATIF : ce pre-check ne declenche JAMAIS de skip automatique (seul le
pre-check LOGS le fait). Tu revois les verdicts 'policy' et decides.

Portee : fiable pour les flux INTERNES. Les flux INTERNET (filtrage par
categorie URL) ressortent REVIEW -> se fier aux logs.

Usage:
    python check_flows_policy.py demandes_clean.csv
    python check_flows_policy.py demandes_clean.csv --only 245,246
    python check_flows_policy.py demandes_clean.csv --json rapport_policy.json
"""

import argparse
import json

from panorama_client import PanoramaClient
from policy_engine import PolicyEngine
from check_flows_panorama import expand_services, to_host
from bulk_create_requests import (
    load_requests,
    row_to_ticket,
    apply_source_object_map,
)


def evaluate_flow(engines, ticket):
    """Evalue un flux sur chaque firewall. Retourne {fw_name: status} + agrege."""
    # Combinaisons (src_host, dst_host, proto, port)
    src_hosts = [h for h, _ in (to_host(s) for s in ticket["sources"]) if h]
    dst_hosts = [h for h, _ in (to_host(d) for d in ticket["destinations"]) if h]
    combos = []
    for proto, port, _ in expand_services(ticket["services"]):
        if port is None:
            continue
        for s in src_hosts:
            for d in dst_hosts:
                combos.append((s, d, proto, int(port)))

    if not combos:
        return {"_aggregate": "NON_TESTABLE"}, {}

    per_fw = {}
    for name, eng in engines.items():
        statuses = set()
        for s, d, proto, port in combos:
            statuses.add(eng.evaluate(s, d, proto, port)["status"])
        # Agrege les combos d'un firewall
        if statuses == {"ALLOWED"}:
            per_fw[name] = "ALLOWED"
        elif "BLOCKED" in statuses:
            per_fw[name] = "BLOCKED"
        elif "REVIEW" in statuses:
            per_fw[name] = "REVIEW"
        elif "ALLOWED" in statuses:
            per_fw[name] = "PARTIAL"
        else:
            per_fw[name] = "NO_MATCH"

    # Agrege multi-firewalls (informatif) : le plus "significatif"
    vals = set(per_fw.values())
    if "BLOCKED" in vals:
        agg = "BLOCKED"
    elif vals == {"ALLOWED"}:
        agg = "ALLOWED"
    elif "ALLOWED" in vals:
        agg = "ALLOWED*"      # autorise par au moins un FW (a confirmer selon chemin)
    elif "REVIEW" in vals:
        agg = "REVIEW"
    else:
        agg = "NO_MATCH"
    return {"_aggregate": agg}, per_fw


def main():
    parser = argparse.ArgumentParser(description="Pre-check policy (informatif) via moteur d'evaluation")
    parser.add_argument("input_file")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--only", help="Ne tester que ces '#'")
    parser.add_argument("--json", dest="json_path", help="Rapport detaille JSON")
    parser.add_argument("--no-write", action="store_true", help="Ne pas ecrire la colonne policy")

    args = parser.parse_args()
    only_ids = {x.strip() for x in args.only.split(",")} if args.only else None

    with open(args.config, "r") as f:
        cfg = json.load(f)
    source_object_map = cfg.get("source_object_map") or {}
    fws = cfg.get("policy_firewalls") or []
    if not fws:
        print("[ERREUR] Aucun 'policy_firewalls' dans config.json.")
        return

    rows = load_requests(args.input_file)
    flows = []
    for row in rows:
        ticket, _ = row_to_ticket(row)
        if ticket is None:
            continue
        if only_ids is not None and (ticket.get("id") or "").strip() not in only_ids:
            continue
        apply_source_object_map(ticket, source_object_map)
        flows.append(ticket)

    if not flows:
        print("[INFO] Aucun flux a evaluer.")
        return

    pano = PanoramaClient(args.config)
    pano.keygen()

    # Charge la policy de chaque firewall UNE fois
    engines = {}
    for fw in fws:
        print(f"[...] Chargement policy {fw['name']} ({fw['serial']})...")
        eng = PolicyEngine(pano, fw["serial"])
        nr = eng.load_firewall_rules()
        eng.load_objects()
        print(f"      {nr} regles chargees.")
        engines[fw["name"]] = eng

    results_by_id, reports, counts = {}, [], {}
    for t in flows:
        rid = t.get("id") or "?"
        agg, per_fw = evaluate_flow(engines, t)
        status = agg["_aggregate"]
        results_by_id[str(rid)] = status
        counts[status] = counts.get(status, 0) + 1
        detail = " ".join(f"{n}={s}" for n, s in per_fw.items())
        print(f"  #{rid:<5} policy={status:<10} [{detail}]")
        reports.append({"id": rid, "policy": status, "per_firewall": per_fw,
                        "sources": t["sources"], "destinations": t["destinations"],
                        "services": t["services"]})

    print(f"\n{'='*40}")
    print("Resume policy (INFORMATIF, pas de skip auto):",
          ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    if not args.no_write:
        _write_policy_column(args.input_file, results_by_id)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport -> {args.json_path}")


def _write_policy_column(input_path, results_by_id):
    """Ecrit la colonne 'policy' (informatif) sans toucher 'deja_autorise'."""
    import csv
    import os
    from bulk_create_requests import read_csv_rows, read_xlsx_rows, _norm
    ext = os.path.splitext(input_path)[1].lower()
    out_path = input_path if ext != ".xlsx" else os.path.splitext(input_path)[0] + "_policy.csv"
    raw = read_xlsx_rows(input_path) if ext == ".xlsx" else read_csv_rows(input_path)
    if not raw:
        return
    headers = list(raw[0].keys())
    id_key = next((h for h in headers if _norm(h) == "#"), None)
    if id_key is None:
        print("[WARN] Colonne '#' introuvable : colonne policy non ecrite.")
        return
    fieldnames = headers + (["policy"] if "policy" not in headers else [])
    for row in raw:
        rid = (row.get(id_key) or "").strip()
        row["policy"] = results_by_id.get(rid, row.get("policy", ""))
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(raw)
    print(f"[OK] Colonne 'policy' ecrite dans {out_path} (informatif).")


if __name__ == "__main__":
    main()

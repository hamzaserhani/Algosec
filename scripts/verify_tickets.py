"""
Post-check : verifie que les tickets CREES dans AlgoSec correspondent bien a ce
qui etait DEMANDE dans le fichier (read-after-write).

Principe:
    1. Relit le fichier de demandes (meme parsing que la creation).
    2. Pour chaque demande, recupere l'ID du ticket (colonne ALGOSEC ou historique).
    3. GET le ticket dans FireFlow (endpoint auto-detecte).
    4. Extrait les sources / destinations / services REELS du ticket.
    5. Compare aux valeurs demandees -> OK ou MISMATCH detaille.

Usage:
    python verify_tickets.py demandes_clean.csv
    python verify_tickets.py demandes_clean.csv --history-dir request_history_prod
    python verify_tickets.py demandes_clean.csv --json rapport_verif.json
"""

import argparse
import json
import re

from algosec_client import AlgosecClient
from inspect_ticket_fields import fetch_ticket
from bulk_create_requests import (
    load_requests,
    row_to_ticket,
    lookup_ticket_id,
    _norm,
)


# Cles portant une adresse/nom dans les items d'une ligne de trafic
LEAF_KEYS = ("name", "address", "ipAddress", "ip", "value")


def _collect_leaf_names(node, out):
    """Collecte recursivement les valeurs 'name/address/...' sous un noeud."""
    if isinstance(node, dict):
        for k in LEAF_KEYS:
            if k in node and isinstance(node[k], str) and node[k].strip():
                out.append(node[k].strip())
        for v in node.values():
            _collect_leaf_names(v, out)
    elif isinstance(node, list):
        for item in node:
            _collect_leaf_names(item, out)


def extract_actual(result):
    """Extrait {sources, destinations, services} reels depuis la reponse GET.

    Cherche recursivement les cles source/destination/service (dans
    originalTraffic/plannedTraffic ou traffic) et collecte leurs valeurs.
    """
    found = {"source": [], "destination": [], "service": []}

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                kl = key.lower()
                for target in found:
                    # 'source', 'sources', 'trafficSource'... -> source
                    if kl == target or kl == target + "s" or kl.endswith(target):
                        names = []
                        _collect_leaf_names(value, names)
                        found[target].extend(names)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(result.get("data", result))
    # dedup en preservant l'ordre
    for k in found:
        seen, uniq = set(), []
        for x in found[k]:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        found[k] = uniq
    return found


def _norm_val(v):
    """Normalise une valeur pour comparaison (espaces, casse)."""
    return re.sub(r"\s+", "", v).lower()


def compare(expected, actual):
    """Compare deux listes. Retourne (manquants, en_trop)."""
    exp = {_norm_val(x): x for x in expected}
    act = {_norm_val(x): x for x in actual}
    missing = [exp[k] for k in exp if k not in act]   # demandes mais absents du ticket
    extra = [act[k] for k in act if k not in exp]     # presents mais non demandes
    return missing, extra


def verify_one(client, req, ticket_id):
    """Verifie une demande contre son ticket. Retourne un dict de resultat."""
    expected, reason = row_to_ticket(req)
    if expected is None:
        return {"id": req.get("id"), "ticket_id": ticket_id,
                "status": "SKIPPED", "reason": reason}
    form_type, result, _ = fetch_ticket(client, ticket_id)
    if result is None:
        return {"id": req.get("id"), "ticket_id": ticket_id, "status": "UNREADABLE"}

    actual = extract_actual(result)
    report = {"id": req.get("id"), "ticket_id": ticket_id, "form_type": form_type,
              "status": "OK", "diffs": {}}

    for field, exp_list in (
        ("sources", expected["sources"]),
        ("destinations", expected["destinations"]),
        ("services", expected["services"]),
    ):
        # sources -> cle 'source' cote reel, etc.
        act_list = actual.get(field[:-1], [])
        missing, extra = compare(exp_list, act_list)
        if missing or extra:
            report["status"] = "MISMATCH"
            report["diffs"][field] = {
                "expected": exp_list,
                "actual": act_list,
                "missing": missing,   # demande mais absent
                "extra": extra,       # present mais non demande
            }
    return report


def main():
    parser = argparse.ArgumentParser(description="Verifie les tickets crees vs le fichier de demandes")
    parser.add_argument("input_file", help="Fichier de demandes (.csv ou .xlsx)")
    parser.add_argument("--config", default="config.json", help="Fichier de config")
    parser.add_argument("--history-dir", default="request_history", help="Dossier d'historique JSON")
    parser.add_argument("--json", dest="json_path", help="Sauve le rapport complet en JSON")
    parser.add_argument("--only", help="Ne verifier qu'un seul # (ex: --only 244)")

    args = parser.parse_args()

    rows = load_requests(args.input_file)

    # Retrouve l'ID ticket par ligne : colonne ALGOSEC prioritaire, sinon historique
    alg_key = None
    if rows:
        alg_key = next((k for k in rows[0] if _norm(k) == "algosec"), None)

    todo = []
    for req in rows:
        rid = (req.get("id") or "").strip()
        if not rid:
            continue
        if args.only and rid != args.only:
            continue
        tid = (req.get(alg_key) if alg_key else "") or lookup_ticket_id(args.history_dir, rid)
        tid = str(tid).strip()
        if tid:
            todo.append((req, tid))

    if not todo:
        print("[INFO] Aucun ticket a verifier (colonne ALGOSEC vide et historique absent ?).")
        return

    print(f"[INFO] Verification de {len(todo)} ticket(s)...")
    client = AlgosecClient(args.config)
    client.authenticate()

    reports = []
    ok = mism = unread = 0
    for req, tid in todo:
        rep = verify_one(client, req, tid)
        reports.append(rep)
        if rep["status"] == "OK":
            ok += 1
            print(f"  [OK]       #{rep['id']} -> ticket {tid}")
        elif rep["status"] == "UNREADABLE":
            unread += 1
            print(f"  [ILLISIBLE] #{rep['id']} -> ticket {tid} (GET impossible)")
        else:
            mism += 1
            print(f"  [MISMATCH] #{rep['id']} -> ticket {tid}")
            for field, d in rep["diffs"].items():
                if d["missing"]:
                    print(f"       {field}: MANQUANT dans le ticket -> {d['missing']}")
                if d["extra"]:
                    print(f"       {field}: EN TROP dans le ticket   -> {d['extra']}")

    print(f"\n{'='*40}")
    print(f"Resume: {ok} OK, {mism} mismatch, {unread} illisible(s) sur {len(todo)} ticket(s)")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport detaille -> {args.json_path}")


if __name__ == "__main__":
    main()

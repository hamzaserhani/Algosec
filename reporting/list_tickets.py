"""
Reporting FireFlow : liste des tickets avec filtres et statistiques.

Recupere les tickets via l'API, applique des filtres (statut, periode, demandeur),
affiche un tableau resume + statistiques, et exporte optionnellement en CSV/JSON.

Usage:
    python list_tickets.py
    python list_tickets.py --status Open --status "In Progress"
    python list_tickets.py --since 2026-01-01 --until 2026-04-30
    python list_tickets.py --requestor jdupont --csv rapport.csv
    python list_tickets.py --json rapport.json --stats
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

# Permet d'importer algosec_client depuis ../scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from algosec_client import AlgosecClient  # noqa: E402


def fetch_tickets(client, status=None, since=None, until=None, requestor=None, limit=None):
    """Recupere les tickets depuis l'API avec filtres optionnels."""
    print("\n[...] Recuperation des tickets...")

    params = []
    if status:
        for s in status:
            params.append(("status", s))
    if since:
        params.append(("createdFrom", since))
    if until:
        params.append(("createdTo", until))
    if requestor:
        params.append(("requestor", requestor))
    if limit:
        params.append(("limit", str(limit)))

    query = "&".join(f"{k}={v}" for k, v in params)
    endpoint = "change-requests" + (f"?{query}" if query else "")

    result = client.get(endpoint)

    if result.get("status") != "Success":
        messages = result.get("messages", [])
        error_msg = messages[0]["message"] if messages else "Erreur inconnue"
        print(f"[ERREUR] Echec recuperation: {error_msg}")
        return []

    data = result.get("data", {})
    tickets = data.get("changeRequests", data) if isinstance(data, dict) else data
    if not isinstance(tickets, list):
        tickets = [tickets]

    print(f"[OK] {len(tickets)} ticket(s) recupere(s).")
    return tickets


def print_table(tickets):
    """Affiche un tableau resume des tickets."""
    if not tickets:
        print("[INFO] Aucun ticket a afficher.")
        return

    print(f"\n{'ID':<10} {'Statut':<20} {'Cree le':<12} {'Demandeur':<20} {'Sujet':<40}")
    print("-" * 102)
    for t in tickets:
        ticket_id = str(t.get("id", t.get("changeRequestId", "?")))[:10]
        status = str(t.get("status", "?"))[:20]
        created = str(t.get("createDate", t.get("created", "?")))[:10]
        requestor = str(t.get("requestor", t.get("createdBy", "?")))[:20]
        subject = str(t.get("subject", "?"))[:40]
        print(f"{ticket_id:<10} {status:<20} {created:<12} {requestor:<20} {subject:<40}")


def compute_stats(tickets):
    """Calcule des statistiques sur les tickets."""
    stats = {
        "total": len(tickets),
        "par_statut": {},
        "par_demandeur": {},
        "par_mois": {},
    }
    for t in tickets:
        status = t.get("status", "Inconnu")
        stats["par_statut"][status] = stats["par_statut"].get(status, 0) + 1

        requestor = t.get("requestor", t.get("createdBy", "Inconnu"))
        stats["par_demandeur"][requestor] = stats["par_demandeur"].get(requestor, 0) + 1

        created = t.get("createDate", t.get("created", ""))
        if isinstance(created, str) and len(created) >= 7:
            mois = created[:7]
            stats["par_mois"][mois] = stats["par_mois"].get(mois, 0) + 1

    return stats


def print_stats(stats):
    """Affiche les statistiques."""
    print(f"\n=== Statistiques ===")
    print(f"Total: {stats['total']} ticket(s)")

    if stats["par_statut"]:
        print(f"\nPar statut:")
        for k, v in sorted(stats["par_statut"].items(), key=lambda x: -x[1]):
            print(f"  {k:<25} {v}")

    if stats["par_demandeur"]:
        print(f"\nPar demandeur (top 10):")
        top = sorted(stats["par_demandeur"].items(), key=lambda x: -x[1])[:10]
        for k, v in top:
            print(f"  {k:<25} {v}")

    if stats["par_mois"]:
        print(f"\nPar mois:")
        for k, v in sorted(stats["par_mois"].items()):
            print(f"  {k:<25} {v}")


def export_csv(tickets, path):
    """Exporte les tickets en CSV."""
    if not tickets:
        print("[WARN] Aucun ticket a exporter.")
        return
    fieldnames = sorted({k for t in tickets for k in t.keys()})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for t in tickets:
            writer.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in t.items()})
    print(f"[OK] Export CSV: {path} ({len(tickets)} lignes)")


def export_json(tickets, path):
    """Exporte les tickets en JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tickets, f, indent=2, ensure_ascii=False, default=str)
    print(f"[OK] Export JSON: {path} ({len(tickets)} tickets)")


def valid_date(s):
    """Valide une date au format YYYY-MM-DD."""
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s
    except ValueError:
        raise argparse.ArgumentTypeError(f"Date invalide '{s}', format attendu: YYYY-MM-DD")


def main():
    parser = argparse.ArgumentParser(description="Reporting des tickets FireFlow")
    parser.add_argument("--config", default="config.json", help="Chemin vers le fichier de config")
    parser.add_argument("--status", action="append", help="Filtre par statut (repetable)")
    parser.add_argument("--since", type=valid_date, help="Date de debut (YYYY-MM-DD)")
    parser.add_argument("--until", type=valid_date, help="Date de fin (YYYY-MM-DD)")
    parser.add_argument("--requestor", help="Filtre par demandeur")
    parser.add_argument("--limit", type=int, help="Nombre max de tickets a recuperer")
    parser.add_argument("--csv", dest="csv_path", help="Exporter en CSV vers ce chemin")
    parser.add_argument("--json", dest="json_path", help="Exporter en JSON vers ce chemin")
    parser.add_argument("--stats", action="store_true", help="Afficher les statistiques")
    parser.add_argument("--no-table", action="store_true", help="Ne pas afficher le tableau")

    args = parser.parse_args()

    client = AlgosecClient(args.config)
    client.authenticate()

    tickets = fetch_tickets(
        client,
        status=args.status,
        since=args.since,
        until=args.until,
        requestor=args.requestor,
        limit=args.limit,
    )

    if not args.no_table:
        print_table(tickets)

    if args.stats:
        print_stats(compute_stats(tickets))

    if args.csv_path:
        export_csv(tickets, args.csv_path)
    if args.json_path:
        export_json(tickets, args.json_path)


if __name__ == "__main__":
    main()

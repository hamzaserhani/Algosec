"""
Creation en masse de tickets Traffic Change Request depuis un fichier CSV.

Format CSV attendu:
    subject,description,sources,destinations,services,action,devices,template

    - sources, destinations, services, devices: separes par "|" si multiples
    - template: optionnel (defaut: "Basic Change Traffic Request")

Usage:
    python bulk_create_tickets.py tickets.csv
    python bulk_create_tickets.py tickets.csv --dry-run
"""

import argparse
import csv
import json
import sys
import time
from algosec_client import AlgosecClient
from create_traffic_ticket import build_traffic_payload, create_ticket


def parse_multi_value(value):
    """Parse une valeur multi-valuee separee par |."""
    if not value or not value.strip():
        return None
    return [v.strip() for v in value.split("|") if v.strip()]


def load_csv(csv_path):
    """Charge et parse le fichier CSV."""
    tickets = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):
            subject = row.get("subject", "").strip()
            if not subject:
                print(f"[WARN] Ligne {i}: sujet manquant, ignoree.")
                continue

            sources = parse_multi_value(row.get("sources", ""))
            destinations = parse_multi_value(row.get("destinations", ""))

            if not sources or not destinations:
                print(f"[WARN] Ligne {i}: source ou destination manquante, ignoree.")
                continue

            ticket = {
                "subject": subject,
                "description": row.get("description", "").strip(),
                "sources": sources,
                "destinations": destinations,
                "services": parse_multi_value(row.get("services", "")) or ["any"],
                "action": row.get("action", "Allow").strip() or "Allow",
                "devices": parse_multi_value(row.get("devices", "")),
                "template": row.get("template", "").strip() or "Basic Change Traffic Request",
            }
            tickets.append(ticket)

    return tickets


def main():
    parser = argparse.ArgumentParser(description="Creation en masse de tickets depuis un CSV")
    parser.add_argument("csv_file", help="Chemin vers le fichier CSV")
    parser.add_argument("--config", default="config.json", help="Chemin vers le fichier de config")
    parser.add_argument("--dry-run", action="store_true", help="Affiche les payloads sans les envoyer")
    parser.add_argument("--delay", type=float, default=1.0, help="Delai entre chaque requete en secondes (defaut: 1s)")

    args = parser.parse_args()

    # Charger le CSV
    tickets = load_csv(args.csv_file)
    print(f"\n[INFO] {len(tickets)} ticket(s) a creer depuis {args.csv_file}")

    if not tickets:
        print("[INFO] Rien a faire.")
        return

    # Authentification
    client = AlgosecClient(args.config)
    if not args.dry_run:
        client.authenticate()

    # Creer les tickets
    success_count = 0
    fail_count = 0

    for i, ticket_data in enumerate(tickets, start=1):
        print(f"\n--- Ticket {i}/{len(tickets)} ---")

        payload = build_traffic_payload(**ticket_data)

        if args.dry_run:
            print(f"  [DRY-RUN] {ticket_data['subject']}")
            print(json.dumps(payload, indent=2))
            continue

        result = create_ticket(client, payload)
        if result and result.get("status") == "Success":
            success_count += 1
        else:
            fail_count += 1

        # Delai entre les requetes pour ne pas surcharger le serveur
        if i < len(tickets):
            time.sleep(args.delay)

    # Resume
    if not args.dry_run:
        print(f"\n{'='*40}")
        print(f"Resume: {success_count} reussi(s), {fail_count} echec(s) sur {len(tickets)} ticket(s)")
    else:
        print(f"\n[DRY-RUN] {len(tickets)} ticket(s) affiches (aucun envoye)")


if __name__ == "__main__":
    main()

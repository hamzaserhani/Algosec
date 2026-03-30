"""
Recuperer le statut et les details d'un ticket FireFlow.

Usage:
    python get_ticket.py 12345
    python get_ticket.py 12345 12346 12347
"""

import argparse
import json
import sys
from algosec_client import AlgosecClient


def get_ticket(client, ticket_id):
    """Recupere les details d'un ticket par son ID."""
    print(f"\n[...] Recuperation du ticket #{ticket_id}...")

    result = client.get(f"change-requests/{ticket_id}")

    if result.get("status") == "Success":
        data = result.get("data", {})
        print(f"\n[OK] Ticket #{ticket_id}")
        print(f"  Sujet:  {data.get('subject', 'N/A')}")
        print(f"  Statut: {data.get('status', 'N/A')}")
        print(f"  Cree:   {data.get('createDate', 'N/A')}")
        print(f"\n  Details complets:")
        print(json.dumps(data, indent=2))
        return data
    else:
        messages = result.get("messages", [])
        error_msg = messages[0]["message"] if messages else "Erreur inconnue"
        print(f"\n[ERREUR] Impossible de recuperer le ticket #{ticket_id}: {error_msg}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Recuperer le statut d'un ticket FireFlow")
    parser.add_argument("ticket_ids", nargs="+", help="ID(s) du/des ticket(s)")
    parser.add_argument("--config", default="config.json", help="Chemin vers le fichier de config")

    args = parser.parse_args()

    client = AlgosecClient(args.config)
    client.authenticate()

    for ticket_id in args.ticket_ids:
        get_ticket(client, ticket_id)


if __name__ == "__main__":
    main()

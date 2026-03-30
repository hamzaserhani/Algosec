"""
Creation de tickets Traffic Change Request via l'API FireFlow.

Usage:
    python create_traffic_ticket.py                         # mode interactif
    python create_traffic_ticket.py --json ticket.json      # depuis un fichier JSON
    python create_traffic_ticket.py --source 10.0.0.0/24 --destination 192.168.1.0/24 --service https --action Allow
"""

import argparse
import json
import sys
from algosec_client import AlgosecClient


def build_traffic_payload(
    subject,
    description="",
    sources=None,
    destinations=None,
    services=None,
    action="Allow",
    devices=None,
    template="Basic Change Traffic Request",
    application="any",
    nat_source=None,
    nat_destination=None,
    nat_port=None,
    nat_type="Static",
):
    """Construit le payload JSON pour un ticket traffic change request."""

    # Champs du ticket
    fields = [
        {"key": "subject", "values": [subject]},
    ]
    if description:
        fields.append({"key": "Change Request Description", "values": [description]})
    if devices:
        fields.append({"name": "devices", "values": devices if isinstance(devices, list) else [devices]})

    # Lignes de trafic
    traffic_line = {
        "source": {
            "items": [{"name": s} for s in (sources or [])]
        },
        "destination": {
            "items": [{"name": d} for d in (destinations or [])]
        },
        "service": {
            "items": [{"name": svc} for svc in (services or ["any"])]
        },
        "application": {
            "items": [{"name": application}]
        },
        "action": action,
    }

    # NAT (optionnel)
    if nat_source or nat_destination or nat_port:
        traffic_line["natDetails"] = {
            "type": nat_type,
        }
        if nat_source:
            traffic_line["natDetails"]["source"] = nat_source if isinstance(nat_source, list) else [nat_source]
        if nat_destination:
            traffic_line["natDetails"]["destination"] = nat_destination if isinstance(nat_destination, list) else [nat_destination]
        if nat_port:
            traffic_line["natDetails"]["port"] = nat_port if isinstance(nat_port, list) else [nat_port]

    payload = {
        "template": template,
        "fields": fields,
        "traffic": [traffic_line],
    }

    return payload


def create_ticket(client, payload):
    """Envoie la requete de creation de ticket."""
    print("\n[...] Creation du ticket en cours...")
    print(f"  Template: {payload['template']}")
    print(f"  Subject:  {payload['fields'][0]['values'][0]}")

    result = client.post("change-requests/traffic", payload)

    if result.get("status") == "Success":
        ticket_data = result.get("data", {})
        ticket_id = ticket_data.get("id", ticket_data.get("changeRequestId", "N/A"))
        print(f"\n[OK] Ticket cree avec succes!")
        print(f"  Ticket ID: {ticket_id}")
        print(f"  Response:  {json.dumps(result, indent=2)}")
        return result
    else:
        messages = result.get("messages", [])
        error_msg = messages[0]["message"] if messages else "Erreur inconnue"
        print(f"\n[ERREUR] Echec creation: {error_msg}")
        print(f"  Response: {json.dumps(result, indent=2)}")
        return None


def interactive_mode(client):
    """Mode interactif pour creer un ticket."""
    print("\n=== Creation de ticket Traffic Change Request (interactif) ===\n")

    subject = input("Sujet du ticket: ").strip()
    if not subject:
        print("[ERREUR] Le sujet est obligatoire.")
        sys.exit(1)

    description = input("Description (optionnel): ").strip()

    sources_input = input("Sources (separes par des virgules, ex: 10.0.0.0/24,10.0.1.0/24): ").strip()
    sources = [s.strip() for s in sources_input.split(",") if s.strip()]

    destinations_input = input("Destinations (separes par des virgules): ").strip()
    destinations = [d.strip() for d in destinations_input.split(",") if d.strip()]

    services_input = input("Services (separes par des virgules, ex: https,tcp/8080) [any]: ").strip()
    services = [s.strip() for s in services_input.split(",") if s.strip()] if services_input else ["any"]

    action = input("Action (Allow/Drop) [Allow]: ").strip() or "Allow"

    devices_input = input("Devices (separes par des virgules, optionnel): ").strip()
    devices = [d.strip() for d in devices_input.split(",") if d.strip()] if devices_input else None

    template = input("Template [Basic Change Traffic Request]: ").strip() or "Basic Change Traffic Request"

    payload = build_traffic_payload(
        subject=subject,
        description=description,
        sources=sources,
        destinations=destinations,
        services=services,
        action=action,
        devices=devices,
        template=template,
    )

    print(f"\n--- Payload ---")
    print(json.dumps(payload, indent=2))

    confirm = input("\nEnvoyer ce ticket ? (o/n) [o]: ").strip().lower()
    if confirm in ("n", "non"):
        print("Annule.")
        sys.exit(0)

    return create_ticket(client, payload)


def main():
    parser = argparse.ArgumentParser(description="Creer un ticket Traffic Change Request AlgoSec")
    parser.add_argument("--config", default="config.json", help="Chemin vers le fichier de config")
    parser.add_argument("--json", dest="json_file", help="Fichier JSON avec le payload complet")
    parser.add_argument("--source", nargs="+", help="Adresses source")
    parser.add_argument("--destination", nargs="+", help="Adresses destination")
    parser.add_argument("--service", nargs="+", default=["any"], help="Services")
    parser.add_argument("--action", default="Allow", choices=["Allow", "Drop"], help="Action")
    parser.add_argument("--subject", help="Sujet du ticket")
    parser.add_argument("--description", default="", help="Description du ticket")
    parser.add_argument("--devices", nargs="+", help="Devices concernes")
    parser.add_argument("--template", default="Basic Change Traffic Request", help="Template du ticket")

    args = parser.parse_args()

    # Authentification
    client = AlgosecClient(args.config)
    client.authenticate()

    # Mode fichier JSON
    if args.json_file:
        with open(args.json_file, "r") as f:
            payload = json.load(f)
        create_ticket(client, payload)
        return

    # Mode ligne de commande
    if args.source and args.destination and args.subject:
        payload = build_traffic_payload(
            subject=args.subject,
            description=args.description,
            sources=args.source,
            destinations=args.destination,
            services=args.service,
            action=args.action,
            devices=args.devices,
            template=args.template,
        )
        create_ticket(client, payload)
        return

    # Mode interactif
    interactive_mode(client)


if __name__ == "__main__":
    main()

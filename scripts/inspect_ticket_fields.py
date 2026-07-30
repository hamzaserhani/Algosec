"""
Inspecte un ticket FireFlow existant pour decouvrir les NOMS EXACTS de ses
champs (template-specifiques). Utile avant de creer des tickets sur un template
dont on ne connait pas les champs obligatoires.

Principe:
    1. GET du ticket existant (fourni par son ID)
    2. Extraction recursive de tous les champs (nom + valeur actuelle)
    3. Affichage du template + tableau des champs
    4. Generation d'un squelette 'fields' pret a coller dans config.json

Usage:
    python inspect_ticket_fields.py 12345
    python inspect_ticket_fields.py 12345 --raw          # dump JSON complet en plus
    python inspect_ticket_fields.py 12345 --json out.json # sauve la reponse brute
"""

import argparse
import json

from algosec_client import AlgosecClient


# Cles possibles selon les versions FireFlow pour le nom et la valeur d'un champ
NAME_KEYS = ("name", "key", "fieldName", "label", "customFieldName")
VALUE_KEYS = ("values", "value", "fieldValues", "fieldValue")


def looks_like_field(d):
    """Un dict ressemble a un champ s'il a une cle de nom ET une cle de valeur."""
    if not isinstance(d, dict):
        return False
    has_name = any(k in d for k in NAME_KEYS)
    has_value = any(k in d for k in VALUE_KEYS)
    return has_name and has_value


def field_name(d):
    for k in NAME_KEYS:
        if k in d and d[k]:
            return str(d[k])
    return "?"


def field_value(d):
    for k in VALUE_KEYS:
        if k in d:
            v = d[k]
            if isinstance(v, list):
                return ", ".join(str(x) for x in v)
            return str(v)
    return ""


def extract_fields(node, found, path=""):
    """Parcourt recursivement le JSON et collecte les champs (nom -> valeur)."""
    if isinstance(node, dict):
        if looks_like_field(node):
            found.append((field_name(node), field_value(node), path))
        for k, v in node.items():
            extract_fields(v, found, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            extract_fields(item, found, f"{path}[{i}]")


def inspect(client, ticket_id, raw=False, json_path=None):
    print(f"\n[...] GET du ticket #{ticket_id}...")
    # Endpoint officiel de lecture FireFlow: change-requests/generic/{id}
    result = client.get(f"change-requests/generic/{ticket_id}")

    if result.get("status") != "Success":
        messages = result.get("messages", [])
        error_msg = messages[0]["message"] if messages else "Erreur inconnue"
        print(f"[ERREUR] Impossible de recuperer #{ticket_id}: {error_msg}")
        return

    # La reponse 'generic' renvoie les infos sous forme de champs {name, values}.
    # On extrait donc a partir de toute la reponse (pas seulement result["data"]).
    data = result.get("data", result) or result

    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[OK] Reponse brute sauvee dans {json_path}")

    # Champs (extraction recursive sur toute la reponse)
    found = []
    extract_fields(data, found)

    # Deduplique par nom en gardant le 1er chemin rencontre
    seen = {}
    for name, value, path in found:
        if name not in seen:
            seen[name] = (value, path)

    # Recherche insensible a la casse d'un champ par nom (pour l'en-tete)
    def field_by(*names):
        lut = {n.lower(): v for n, (v, _) in seen.items()}
        for n in names:
            if n.lower() in lut:
                return lut[n.lower()]
        return "?"

    # Infos generales (au niveau racine OU dans les champs)
    print(f"\n=== Ticket #{ticket_id} ===")
    print(f"  Sujet    : {field_by('subject', 'Subject')}")
    print(f"  Statut   : {field_by('status', 'Status')}")
    print(f"  Template : {field_by('Ticket Template Name', 'template', 'Workflow', 'Form Type')}")

    print(f"\n=== Champs detectes ({len(seen)}) ===")
    print(f"{'NOM DU CHAMP':<40} {'VALEUR ACTUELLE':<30} EMPLACEMENT")
    print("-" * 100)
    for name, (value, path) in seen.items():
        print(f"{name[:39]:<40} {value[:29]:<30} {path}")

    # Squelette config.json 'fields' (champs hors champs systeme evidents)
    system = {"subject", "Change Request Description", "devices", "action",
              "source", "destination", "service", "user", "application"}
    skeleton = {name: value for name, (value, _) in seen.items() if name not in system}
    print(f"\n=== Squelette pour config.json (a ajuster) ===")
    print(json.dumps({"fields": skeleton}, indent=4, ensure_ascii=False))

    if raw:
        print(f"\n=== JSON brut ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Inspecte les champs d'un ticket FireFlow existant")
    parser.add_argument("ticket_ids", nargs="+", help="ID(s) du/des ticket(s) a inspecter")
    parser.add_argument("--config", default="config.json", help="Fichier de config")
    parser.add_argument("--raw", action="store_true", help="Affiche aussi le JSON brut complet")
    parser.add_argument("--json", dest="json_path", help="Sauve la reponse brute dans ce fichier")

    args = parser.parse_args()

    client = AlgosecClient(args.config)
    client.authenticate()

    for tid in args.ticket_ids:
        inspect(client, tid, raw=args.raw, json_path=args.json_path)


if __name__ == "__main__":
    main()

"""
Creation en masse de tickets Traffic Change Request depuis le format "Request"
(tracker metier UCB), en CSV ou XLSX.

Colonnes attendues (l'ordre importe peu, le matching se fait sur le nom d'en-tete):
    #, Purpose, Status, source, application, Target, By when,
    Source IP, Target IP, TCP-IP range, F/W Application, ...

Mapping vers le ticket:
    Purpose        -> subject
    Source IP      -> sources        (multi-valeurs: | , ; ou retour ligne)
    Target IP      -> destinations   (idem)
    TCP-IP range   -> port(s)  --\\
    F/W Application-> protocole  --> service "tcp/<port>" (ou udp si indique)
    Status/source/application/Target/By when -> description (contexte)
    action  = Allow (fixe, pas de colonne dans ce format)
    template= Basic Change Traffic Request

Regles:
    - Une ligne SANS Source IP OU SANS Target IP est ignoree (warning).
    - Chaque demande creee est enregistree en JSON dans le dossier d'historique
      (defaut: request_history/). Une demande deja presente dans l'historique
      est sautee (idempotent), sauf --force.

Usage:
    python bulk_create_requests.py examples/Req_to_create.xlsx --dry-run
    python bulk_create_requests.py demandes.csv
    python bulk_create_requests.py demandes.csv --history-dir request_history --force
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import time

from algosec_client import AlgosecClient
from create_traffic_ticket import build_traffic_payload, create_ticket


# --- Lecture des fichiers -------------------------------------------------

# Nom d'en-tete normalise -> cle canonique
HEADER_MAP = {
    "#": "id",
    "purpose": "purpose",
    "status": "status",
    "source": "source_app",
    "application": "application",
    "target": "target_host",
    "by when": "by_when",
    "source ip": "source_ip",
    "target ip": "target_ip",
    "tcp-ip range": "port",
    "f/w application": "fw_app",
}


def _norm(header):
    """Normalise un en-tete pour le matching (minuscule, espaces compresses)."""
    return re.sub(r"\s+", " ", (header or "").strip().lower())


def _canonize_row(raw_row):
    """Transforme une ligne {en-tete brut: valeur} en {cle canonique: valeur}."""
    row = {}
    for key, value in raw_row.items():
        canon = HEADER_MAP.get(_norm(key))
        if canon:
            row[canon] = (value or "").strip()
    return row


def read_csv_rows(path):
    """Lit un CSV en ignorant d'eventuelles lignes vides en tete."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        # Saute les lignes totalement vides avant l'en-tete
        lines = [ln for ln in f]
    # Trouve la premiere ligne non vide = en-tete
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    reader = csv.DictReader(lines[start:])
    return [dict(r) for r in reader]


def read_xlsx_rows(path):
    """
    Lit la 1ere feuille d'un .xlsx sans dependance externe (zipfile + regex).
    Evite openpyxl (souvent absent) et le parseur XML de la stdlib (casse sur
    certaines builds Python 3.14). Suffisant pour des feuilles de donnees simples.
    """
    import zipfile

    def _unescape(s):
        return (
            s.replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&apos;", "'")
            .replace("&amp;", "&")
        )

    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            ss_xml = z.read("xl/sharedStrings.xml").decode("utf-8")
            for si in re.findall(r"<si>(.*?)</si>", ss_xml, re.S):
                text = "".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.S))
                shared.append(_unescape(text))

        sheet_xml = z.read("xl/worksheets/sheet1.xml").decode("utf-8")

    def _col_letters(ref):
        m = re.match(r"([A-Z]+)", ref)
        return m.group(1) if m else "A"

    def _col_index(letters):
        idx = 0
        for ch in letters:
            idx = idx * 26 + (ord(ch) - ord("A") + 1)
        return idx - 1

    matrix = []
    for row_xml in re.findall(r"<row[^>]*>(.*?)</row>", sheet_xml, re.S):
        cells = {}
        max_idx = -1
        for ref, attrs, body in re.findall(
            r'<c r="([A-Z]+\d+)"([^>]*)>(.*?)</c>', row_xml, re.S
        ):
            v = re.search(r"<v>(.*?)</v>", body, re.S)
            if not v:
                continue
            t = re.search(r't="([^"]+)"', attrs)
            raw = v.group(1)
            value = shared[int(raw)] if (t and t.group(1) == "s") else raw
            col = _col_index(_col_letters(ref))
            cells[col] = _unescape(value) if not (t and t.group(1) == "s") else value
            max_idx = max(max_idx, col)
        matrix.append([cells.get(i, "") for i in range(max_idx + 1)] if max_idx >= 0 else [])

    # 1ere ligne non vide = en-tete
    header = None
    data_rows = []
    for cells in matrix:
        if header is None:
            if any(c.strip() for c in cells):
                header = cells
            continue
        # Pad la ligne a la longueur de l'en-tete
        padded = cells + [""] * (len(header) - len(cells))
        data_rows.append({header[i]: padded[i] for i in range(len(header))})
    return data_rows


def load_requests(path):
    """Charge et canonise les lignes depuis un CSV ou XLSX."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xlsx":
        raw_rows = read_xlsx_rows(path)
    elif ext in (".csv", ".txt", ""):
        raw_rows = read_csv_rows(path)
    else:
        raise ValueError(f"Extension non supportee: {ext} (attendu .csv ou .xlsx)")
    return [_canonize_row(r) for r in raw_rows]


# --- Mapping vers le payload ---------------------------------------------

def parse_multi_value(value):
    """Parse une cellule multi-valuee separee par | , ; ou retour ligne."""
    if not value or not value.strip():
        return None
    parts = re.split(r"[|,;\n\r]+", value)
    return [p.strip() for p in parts if p.strip()]


def build_services(port_cell, fw_app):
    """Construit la liste de services 'proto/port' a partir du port et du F/W App."""
    ports = parse_multi_value(port_cell)
    if not ports:
        return ["any"]
    proto = "udp" if fw_app and "udp" in fw_app.lower() else "tcp"
    return [f"{proto}/{p}" for p in ports]


def build_description(row):
    """Compose une description lisible a partir des colonnes de contexte."""
    parts = []
    for label, key in (
        ("Status", "status"),
        ("Source app", "source_app"),
        ("Application", "application"),
        ("Target", "target_host"),
        ("F/W", "fw_app"),
        ("By when", "by_when"),
    ):
        val = row.get(key, "")
        if val:
            parts.append(f"{label}: {val}")
    return " | ".join(parts)


def row_to_ticket(row):
    """Transforme une ligne canonisee en dict de ticket, ou None si a ignorer."""
    subject = row.get("purpose", "").strip()
    sources = parse_multi_value(row.get("source_ip", ""))
    destinations = parse_multi_value(row.get("target_ip", ""))

    if not subject:
        return None, "sujet (Purpose) manquant"
    if not sources or not destinations:
        return None, "Source IP ou Target IP manquante"

    ticket = {
        "id": row.get("id", "").strip(),
        "subject": subject,
        "description": build_description(row),
        "sources": sources,
        "destinations": destinations,
        "services": build_services(row.get("port", ""), row.get("fw_app", "")),
        "action": "Allow",
        "devices": None,
        "template": "Basic Change Traffic Request",
    }
    return ticket, None


# --- Historique -----------------------------------------------------------

def history_key(ticket):
    """Cle unique d'une demande: le '#' si present, sinon un hash du contenu."""
    if ticket.get("id"):
        return re.sub(r"[^\w.-]", "_", ticket["id"])
    payload = "|".join([
        ticket["subject"],
        ",".join(ticket["sources"]),
        ",".join(ticket["destinations"]),
        ",".join(ticket["services"]),
    ])
    return "h_" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def history_path(history_dir, ticket):
    return os.path.join(history_dir, f"{history_key(ticket)}.json")


def already_created(history_dir, ticket):
    return os.path.exists(history_path(history_dir, ticket))


def record_history(history_dir, ticket, payload, result):
    """Ecrit le JSON d'historique de la demande creee."""
    os.makedirs(history_dir, exist_ok=True)
    data = result.get("data", {}) if result else {}
    entry = {
        "id": ticket.get("id"),
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "subject": ticket["subject"],
        "sources": ticket["sources"],
        "destinations": ticket["destinations"],
        "services": ticket["services"],
        "ticket_id": data.get("id", data.get("changeRequestId")),
        "status": result.get("status") if result else None,
        "payload": payload,
    }
    with open(history_path(history_dir, ticket), "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)


# --- Main -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Creation en masse de tickets depuis le format Request (CSV/XLSX)"
    )
    parser.add_argument("input_file", help="Chemin vers le fichier CSV ou XLSX")
    parser.add_argument("--config", default="config.json", help="Fichier de config")
    parser.add_argument("--dry-run", action="store_true", help="Affiche les payloads sans les envoyer")
    parser.add_argument("--delay", type=float, default=1.0, help="Delai entre requetes (s)")
    parser.add_argument("--history-dir", default="request_history", help="Dossier d'historique JSON")
    parser.add_argument("--force", action="store_true", help="Recree meme si deja dans l'historique")

    args = parser.parse_args()

    rows = load_requests(args.input_file)

    tickets = []
    skipped = 0
    for i, row in enumerate(rows, start=2):  # start=2: ligne 1 = en-tete
        ticket, reason = row_to_ticket(row)
        if ticket is None:
            if reason:  # ligne de bruit sans purpose -> silencieux si totalement vide
                if any(row.values()):
                    print(f"[WARN] Ligne {i}: {reason}, ignoree.")
                    skipped += 1
            continue
        tickets.append(ticket)

    print(f"\n[INFO] {len(tickets)} demande(s) valide(s), {skipped} ignoree(s) depuis {args.input_file}")

    if not tickets:
        print("[INFO] Rien a faire.")
        return

    client = AlgosecClient(args.config)
    if not args.dry_run:
        client.authenticate()

    success_count = 0
    fail_count = 0
    skipped_history = 0

    for i, ticket in enumerate(tickets, start=1):
        print(f"\n--- Demande {i}/{len(tickets)} (#{ticket.get('id') or '?'}) ---")

        if not args.force and already_created(args.history_dir, ticket):
            print(f"  [SKIP] Deja creee (historique: {history_path(args.history_dir, ticket)})")
            skipped_history += 1
            continue

        payload = build_traffic_payload(
            subject=ticket["subject"],
            description=ticket["description"],
            sources=ticket["sources"],
            destinations=ticket["destinations"],
            services=ticket["services"],
            action=ticket["action"],
            devices=ticket["devices"],
            template=ticket["template"],
        )

        if args.dry_run:
            print(f"  [DRY-RUN] {ticket['subject']}")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            continue

        result = create_ticket(client, payload)
        if result and result.get("status") == "Success":
            success_count += 1
            record_history(args.history_dir, ticket, payload, result)
        else:
            fail_count += 1

        if i < len(tickets):
            time.sleep(args.delay)

    if not args.dry_run:
        print(f"\n{'='*40}")
        print(
            f"Resume: {success_count} reussi(s), {fail_count} echec(s), "
            f"{skipped_history} deja existant(s) sur {len(tickets)} demande(s)"
        )
    else:
        print(f"\n[DRY-RUN] {len(tickets)} demande(s) affichee(s) (aucune envoyee)")


if __name__ == "__main__":
    main()

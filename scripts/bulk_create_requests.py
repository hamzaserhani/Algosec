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
    """Lit un CSV (encodage robuste) en ignorant les lignes vides en tete."""
    import io

    # Excel exporte souvent en Windows-1252 (cp1252), pas en UTF-8.
    text = None
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            with open(path, "r", encoding=enc, newline="") as f:
                text = f.read()
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ValueError(f"Impossible de decoder {path} (encodage non reconnu)")

    buf = io.StringIO(text)
    # Saute les lignes totalement vides avant l'en-tete
    pos = buf.tell()
    line = buf.readline()
    while line and not line.strip():
        pos = buf.tell()
        line = buf.readline()
    buf.seek(pos)

    reader = csv.DictReader(buf)
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


def merge_continuation_rows(rows):
    """Fusionne les lignes de continuation dans la demande precedente.

    Dans le format reel, une demande peut s'etaler sur plusieurs lignes : la
    1ere porte le '#' (et le Purpose), les suivantes ont '#'/Purpose vides mais
    ajoutent des valeurs (IP, ports...) dans certaines colonnes. On accumule ces
    valeurs (separees par un retour ligne) dans la demande courante.
    """
    merged = []
    for row in rows:
        if not any((v or "").strip() for v in row.values()):
            continue  # ligne totalement vide
        # Debut d'une nouvelle demande si '#' ou Purpose est renseigne
        is_start = bool((row.get("id") or "").strip() or (row.get("purpose") or "").strip())
        if is_start or not merged:
            merged.append(dict(row))
        else:
            current = merged[-1]
            for key, value in row.items():
                value = (value or "").strip()
                if not value:
                    continue
                prev = (current.get(key) or "").strip()
                current[key] = f"{prev}\n{value}" if prev else value
    return merged


def load_requests(path):
    """Charge et canonise les lignes depuis un CSV ou XLSX."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xlsx":
        raw_rows = read_xlsx_rows(path)
    elif ext in (".csv", ".txt", ""):
        raw_rows = read_csv_rows(path)
    else:
        raise ValueError(f"Extension non supportee: {ext} (attendu .csv ou .xlsx)")
    canon = [_canonize_row(r) for r in raw_rows]
    return merge_continuation_rows(canon)


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
    """Description = Purpose + un contexte court (source -> cible, application)."""
    purpose = (row.get("purpose") or "").strip()
    src = (row.get("source_app") or "").strip()
    tgt = (row.get("target_host") or "").strip()
    app = (row.get("application") or "").strip()

    context = []
    if src or tgt:
        context.append(f"{src or '?'} -> {tgt or '?'}")
    if app:
        context.append(app)

    if purpose and context:
        return f"{purpose} | " + " | ".join(context)
    return purpose or " | ".join(context)


def substitute_placeholders(value, ticket):
    """Remplace {purpose}/{subject}/{description} dans une valeur de config."""
    if not isinstance(value, str):
        return value
    return (
        value.replace("{purpose}", ticket["subject"])
        .replace("{subject}", ticket["subject"])
        .replace("{description}", ticket["description"])
    )


def _dedupe(seq):
    """Supprime les doublons en preservant l'ordre."""
    seen, out = set(), []
    for x in (seq or []):
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def row_to_ticket(row):
    """Transforme une ligne canonisee en dict de ticket, ou None si a ignorer."""
    subject = row.get("purpose", "").strip()
    sources = parse_multi_value(row.get("source_ip", ""))
    destinations = parse_multi_value(row.get("target_ip", ""))

    if not subject:
        return None, "sujet (Purpose) manquant"
    if not sources or not destinations:
        return None, "Source IP ou Target IP manquante"

    # Dedoublonnage (AlgoSec rejette une valeur repetee: DUPLICATED_VALUE_IN_LINE)
    ticket = {
        "id": row.get("id", "").strip(),
        "subject": subject,
        "description": build_description(row),
        "sources": _dedupe(sources),
        "destinations": _dedupe(destinations),
        "services": _dedupe(build_services(row.get("port", ""), row.get("fw_app", ""))),
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


def _extract_error_message(exc):
    """Extrait le(s) message(s) FireFlow d'une exception, sinon la 1ere ligne."""
    resp = getattr(exc, "response", None)
    if resp is not None:
        try:
            body = resp.json()
            msgs = body.get("messages") or []
            if msgs:
                return " ; ".join(
                    f"{m.get('code', '')}: {m.get('message', '')}".strip(": ")
                    for m in msgs
                )
        except Exception:
            pass
    return str(exc).splitlines()[0]


def lookup_ticket_id(history_dir, rid):
    """Retourne l'ID du ticket cree pour ce '#' (depuis l'historique), ou ''."""
    rid = (rid or "").strip()
    if not rid:
        return ""
    key = re.sub(r"[^\w.-]", "_", rid)
    path = os.path.join(history_dir, f"{key}.json")
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("ticket_id") or "")
    except Exception:
        return ""


def write_tracking(input_path, history_dir):
    """Ajoute/remplit une colonne 'ALGOSEC' avec l'ID du ticket cree par ligne.

    Preserve la structure et toutes les colonnes du fichier source. Pour un
    .xlsx (non reinscriptible ici), ecrit un CSV de suivi a cote.
    """
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".xlsx":
        raw = read_xlsx_rows(input_path)
        out_path = os.path.splitext(input_path)[0] + "_tracking.csv"
    else:
        raw = read_csv_rows(input_path)
        out_path = input_path

    if not raw:
        return

    headers = list(raw[0].keys())
    id_key = next((h for h in headers if _norm(h) == "#"), None)
    if id_key is None:
        print("[WARN] Colonne '#' introuvable : suivi ALGOSEC non ecrit.")
        return

    fieldnames = headers + (["ALGOSEC"] if "ALGOSEC" not in headers else [])
    filled = 0
    for row in raw:
        tid = lookup_ticket_id(history_dir, row.get(id_key, ""))
        if tid:
            row["ALGOSEC"] = tid
            filled += 1
        else:
            row.setdefault("ALGOSEC", row.get("ALGOSEC", ""))

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(raw)

    print(f"[OK] Colonne ALGOSEC mise a jour dans {out_path} ({filled} ticket(s) renseigne(s)).")


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
    parser.add_argument("--template", help="Force le template FireFlow (sinon celui du CSV / defaut)")
    parser.add_argument("--no-track", action="store_true",
                        help="Ne pas ecrire l'ID du ticket dans la colonne ALGOSEC du fichier source")

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
    failures = []  # (id, message) pour le recap final

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
            users=[client.default_user],
            action=ticket["action"],
            devices=ticket["devices"],
            template=args.template or client.default_template,
            custom_fields=[
                {"name": name, "values": substitute_placeholders(value, ticket)}
                for name, value in client.custom_fields.items()
            ],
            line_fields=[
                {"name": name, "values": substitute_placeholders(value, ticket)}
                for name, value in client.traffic_fields.items()
            ],
        )

        if args.dry_run:
            print(f"  [DRY-RUN] {ticket['subject']}")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            continue

        # Une demande fautive ne doit pas interrompre le lot : on capture,
        # on compte l'echec, et on continue avec les demandes suivantes.
        try:
            result = create_ticket(client, payload)
        except Exception as e:
            msg = _extract_error_message(e)
            print(f"  [ERREUR] Creation echouee: {msg}")
            fail_count += 1
            failures.append((ticket.get("id") or "?", msg))
            result = None
        else:
            if result and result.get("status") == "Success":
                success_count += 1
                record_history(args.history_dir, ticket, payload, result)
            else:
                fail_count += 1
                failures.append((ticket.get("id") or "?", "reponse non-Success"))

        if i < len(tickets):
            time.sleep(args.delay)

    if not args.dry_run:
        print(f"\n{'='*40}")
        print(
            f"Resume: {success_count} reussi(s), {fail_count} echec(s), "
            f"{skipped_history} deja existant(s) sur {len(tickets)} demande(s)"
        )
        if failures:
            print(f"\nEchecs ({len(failures)}) - a corriger puis relancer :")
            for rid, msg in failures:
                print(f"  - #{rid}: {msg}")
        if not args.no_track:
            write_tracking(args.input_file, args.history_dir)
    else:
        print(f"\n[DRY-RUN] {len(tickets)} demande(s) affichee(s) (aucune envoyee)")


if __name__ == "__main__":
    main()

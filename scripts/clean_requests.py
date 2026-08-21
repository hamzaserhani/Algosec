"""
Nettoie un fichier de demandes (format Req_to_create) SANS perdre de donnees.

Ce qu'il fait :
  - Gere l'encodage Excel (cp1252) et les demandes multi-lignes (fusion des
    lignes de continuation) en reutilisant le meme lecteur que la creation.
  - Normalise les IP : extrait l'IP de 'hostname [1.2.3.4]' -> '1.2.3.4'.
  - Normalise les ports : extrait numeros/plages, ignore les annotations
    comme '(HTTPS SSL)' ou 'TCP '. Ce qui n'est pas numerique est signale.
  - Ecrit un CSV propre, 1 ligne par demande, valeurs multiples jointes par '|'.

Non destructif :
  - Le fichier d'origine n'est jamais modifie (sortie dans un nouveau fichier).
  - Les valeurs brutes sont conservees dans des colonnes '_orig ...'.
  - Tout ce qui necessite une intervention manuelle est liste dans un rapport.

Usage:
    python clean_requests.py Req_to_create.csv -o demandes_clean.csv
    python clean_requests.py Req_to_create.xlsx -o demandes_clean.csv
"""

import argparse
import csv
import re

from bulk_create_requests import (
    read_csv_rows,
    read_xlsx_rows,
    _canonize_row,
    merge_continuation_rows,
)

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?")

# Ordre des colonnes de sortie + cle canonique correspondante
OUT_COLUMNS = [
    ("#", "id"),
    ("Purpose", "purpose"),
    ("Status", "status"),
    ("source", "source_app"),
    ("application", "application"),
    ("Target", "target_host"),
    ("By when", "by_when"),
    ("Source IP", "source_ip"),
    ("Target IP", "target_ip"),
    ("TCP-IP range", "port"),
    ("F/W Application", "fw_app"),
]

ORIG_COLUMNS = ["_orig Source IP", "_orig Target IP", "_orig TCP-IP range"]


def split_values(cell):
    return [p.strip() for p in re.split(r"[|,;\n\r]+", cell or "") if p.strip()]


RANGE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.I
)


def clean_hosts(cell):
    """Nettoie une cellule d'IP/hosts SANS perdre de valeurs.

    Gere : plusieurs IP separees par espace, plages 'A to B' -> 'A-B',
    'hostname (1.2.3.4)' / 'hostname [1.2.3.4]' -> '1.2.3.4'.
    """
    out, warns = [], []
    for part in split_values(cell):
        part = part.strip()
        if not part:
            continue

        # Plage explicite "A to B" -> "A-B"
        mr = RANGE_RE.match(part)
        if mr:
            rng = f"{mr.group(1)}-{mr.group(2)}"
            out.append(rng)
            warns.append(f"plage '{part}' -> '{rng}'")
            continue

        ips = IP_RE.findall(part)
        if not ips:
            out.append(part)  # pas d'IP (hostname/URL) -> garde tel quel, signale
            warns.append(f"valeur sans IP conservee telle quelle: '{part}'")
        elif len(ips) == 1 and ips[0] == part:
            out.append(part)  # deja une IP / CIDR propre
        else:
            # une ou plusieurs IP noyees dans du texte / separees par espace
            out.extend(ips)
            warns.append(f"'{part}' -> {ips}")
    return out, warns


def clean_ports(cell):
    """Extrait ports/plages. Retourne (liste_propre, valeurs_non_reconnues)."""
    out, unknown = [], []
    for part in split_values(cell):
        stripped = re.sub(r"\(.*?\)", "", part)  # enleve '(HTTPS SSL)' etc.
        nums = re.findall(r"\d+(?:-\d+)?", stripped)
        if nums:
            out.extend(nums)
        elif "default" in part.lower():
            # 'default SSL' / 'application default' : l'API refuse le service
            # 'application-default' dans ce flux (exige une application + doit
            # etre seul). On ne produit rien -> le service tombe sur 'any'
            # (ou sur les ports numeriques presents dans la meme cellule).
            unknown.append(part)
        else:
            unknown.append(part)  # non reconnu -> a mapper a la main
    return out, unknown


def load_merged(path):
    import os
    ext = os.path.splitext(path)[1].lower()
    raw = read_xlsx_rows(path) if ext == ".xlsx" else read_csv_rows(path)
    canon = [_canonize_row(r) for r in raw]
    return merge_continuation_rows(canon)


def main():
    parser = argparse.ArgumentParser(description="Nettoie un fichier de demandes sans perdre de donnees")
    parser.add_argument("input_file", help="Fichier a nettoyer (.csv ou .xlsx)")
    parser.add_argument("-o", "--output", default="demandes_clean.csv", help="Fichier de sortie propre")

    args = parser.parse_args()

    requests_rows = load_merged(args.input_file)

    report = []
    seen_ids = {}
    out_rows = []

    for req in requests_rows:
        rid = (req.get("id") or "").strip()
        label = f"#{rid or '?'} ({(req.get('purpose') or '').strip()[:40]})"

        src, w_src = clean_hosts(req.get("source_ip", ""))
        dst, w_dst = clean_hosts(req.get("target_ip", ""))
        ports, unknown = clean_ports(req.get("port", ""))

        row = {name: (req.get(key) or "").replace("\n", " ").strip() for name, key in OUT_COLUMNS}
        row["Source IP"] = "|".join(src)
        row["Target IP"] = "|".join(dst)
        row["TCP-IP range"] = "|".join(ports)
        row["_orig Source IP"] = (req.get("source_ip") or "").replace("\n", " / ").strip()
        row["_orig Target IP"] = (req.get("target_ip") or "").replace("\n", " / ").strip()
        row["_orig TCP-IP range"] = (req.get("port") or "").replace("\n", " / ").strip()
        out_rows.append(row)

        for w in w_src:
            report.append(f"{label} SOURCE  {w}")
        for w in w_dst:
            report.append(f"{label} DEST    {w}")
        if unknown:
            report.append(f"{label} PORTS non numeriques (a mapper a la main): {unknown}")
        if not src or not dst:
            report.append(f"{label} !! IP source ou destination manquante -> ligne ignoree a la creation")
        if rid:
            seen_ids.setdefault(rid, []).append(label)

    for rid, labels in seen_ids.items():
        if len(labels) > 1:
            report.append(f"#{rid} DOUBLON ({len(labels)}x) -> l'historique n'en creera qu'un seul")

    headers = [name for name, _ in OUT_COLUMNS] + ORIG_COLUMNS
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"\n[OK] {len(out_rows)} demande(s) nettoyee(s) -> {args.output}")
    print(f"[INFO] Le fichier d'origine ({args.input_file}) n'a pas ete modifie.")
    print(f"[INFO] Colonnes _orig conservees pour audit (ignorees a la creation).")

    if report:
        print(f"\n=== RAPPORT ({len(report)} point(s) a verifier) ===")
        for line in report:
            print(f"  - {line}")
    else:
        print("\n[OK] Rien a signaler.")

    print(f"\nProchaine etape:")
    print(f"  python scripts/bulk_create_requests.py {args.output} --dry-run")


if __name__ == "__main__":
    main()

"""
Pre-check des flux via Panorama (test security-policy-match) - verdict LIVE.

Lit les demandes du fichier (memes flux que la creation), deplie chaque flux en
(source, destination, protocole, port) et interroge Panorama pour le verdict reel
(App-ID aware) sur un firewall cible.

Contraintes PAN-OS : destination-port et protocol = entiers uniques.
    - 'tcp/443'        -> proto tcp, port 443
    - 'tcp/3200-3299'  -> plage : on teste le 1er port (representatif) + warning
    - 'any'            -> pas de port : non testable ici (flag)

Ciblage : pour l'instant --target <serial> (un firewall). L'auto-path viendra
apres (mapping du chemin). Un flux est ALLOWED seulement si TOUTES les
combinaisons testees renvoient action=allow.

Usage (validation d'un flux connu) :
    python check_flows_panorama.py demandes_clean.csv --only 108 \
        --target 1600UD8LGE4IBMP --raw
    python check_flows_panorama.py demandes_clean.csv --only 108 \
        --target 1600UD8LGE4IBMP --app ssl
"""

import argparse
import ipaddress
import json
import re

from panorama_client import PanoramaClient
from bulk_create_requests import (
    load_requests,
    row_to_ticket,
    apply_source_object_map,
)


def to_host(value):
    """Convertit une valeur source/dest en IP unique testable par PAN-OS.

    PAN-OS test-policy-match exige /32 ou sans masque. Retourne (ip, note).
      - IP simple / /32          -> telle quelle
      - subnet 10.1.156.0/24     -> 1er hote (10.1.156.1) + note 'representatif'
      - plage 'a-b'              -> 1re IP + note
      - hostname/objet nomme     -> None + note (non testable ici)
    """
    v = (value or "").strip()
    # Plage "a-b" -> 1re IP
    if "-" in v and "/" not in v:
        v = v.split("-", 1)[0].strip()
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            if net.prefixlen == 32:
                return str(net.network_address), None
            host = net.network_address + 1  # 1er hote utilisable
            return str(host), f"subnet {value} -> hote representatif {host}"
        ip = ipaddress.ip_address(v)
        return str(ip), None
    except ValueError:
        return None, f"'{value}' non testable (pas une IP - objet/hostname)"


def expand_services(services):
    """Convertit ['tcp/443','tcp/3200-3299','any'] -> [(proto,port,note), ...]."""
    out = []
    for svc in services or []:
        s = svc.strip().lower()
        if s == "any" or not s:
            out.append(("tcp", None, "service 'any' non testable (port requis)"))
            continue
        m = re.match(r"(tcp|udp|icmp)?/?(\d+)(?:-(\d+))?$", s)
        if not m:
            out.append((None, None, f"service non reconnu: '{svc}'"))
            continue
        proto = m.group(1) or "tcp"
        lo, hi = m.group(2), m.group(3)
        if hi:
            out.append((proto, lo, f"plage {lo}-{hi} : teste le port {lo} (representatif)"))
        else:
            out.append((proto, lo, None))
    return out


def check_flow(pano, target, ticket, application=None, raw=False):
    """Teste toutes les combinaisons src x dst x service. Retourne un dict de resultat."""
    notes = []
    # Convertit sources/destinations en IP uniques testables
    src_hosts, dst_hosts = [], []
    for s in ticket["sources"]:
        ip, note = to_host(s)
        if note:
            notes.append(f"SOURCE {note}")
        if ip:
            src_hosts.append(ip)
    for d in ticket["destinations"]:
        ip, note = to_host(d)
        if note:
            notes.append(f"DEST {note}")
        if ip:
            dst_hosts.append(ip)

    combos = []
    for proto, port, note in expand_services(ticket["services"]):
        if note:
            notes.append(note)
        if port is None or proto is None:
            continue
        for src in src_hosts:
            for dst in dst_hosts:
                combos.append((src, dst, proto, port))

    if not combos:
        return {"id": ticket.get("id"), "status": "NON_TESTABLE", "notes": notes, "details": []}

    details = []
    verdicts = set()
    for src, dst, proto, port in combos:
        try:
            rule, action, rawxml = pano.test_policy_match(target, src, dst, port, proto, application)
        except Exception as e:
            details.append({"src": src, "dst": dst, "svc": f"{proto}/{port}",
                            "rule": None, "action": "ERROR", "error": str(e).splitlines()[0]})
            verdicts.add("ERROR")
            continue
        if raw:
            print(f"\n--- {src} -> {dst} {proto}/{port} ---")
            print(rawxml)
        details.append({"src": src, "dst": dst, "svc": f"{proto}/{port}",
                        "rule": rule, "action": action})
        verdicts.add((action or "none").lower())

    # Verdict global (conservateur) : ALLOWED si TOUT est 'allow'
    if verdicts == {"allow"}:
        status = "ALLOWED"
    elif "deny" in verdicts and "allow" in verdicts:
        status = "PARTIAL"
    elif "deny" in verdicts:
        status = "BLOCKED"
    elif "error" in verdicts:
        status = "ERROR"
    else:
        status = "UNKNOWN"
    return {"id": ticket.get("id"), "status": status, "notes": notes, "details": details}


def main():
    parser = argparse.ArgumentParser(description="Pre-check des flux via Panorama test-policy-match")
    parser.add_argument("input_file", help="Fichier de demandes (.csv/.xlsx)")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--only", help="Ne tester que ces '#' (liste separee par virgules)")
    parser.add_argument("--target", required=True, help="Serial du firewall cible")
    parser.add_argument("--app", help="App-ID a tester (ex: ssl, web-browsing)")
    parser.add_argument("--raw", action="store_true", help="Affiche le XML brut de chaque test")
    parser.add_argument("--json", dest="json_path", help="Sauve le rapport en JSON")

    args = parser.parse_args()
    only_ids = {x.strip() for x in args.only.split(",")} if args.only else None

    with open(args.config, "r") as f:
        source_object_map = json.load(f).get("source_object_map") or {}

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
        print("[INFO] Aucun flux a tester.")
        return

    print(f"[INFO] {len(flows)} flux a tester sur le firewall {args.target}.")
    pano = PanoramaClient(args.config)
    pano.keygen()

    reports = []
    for t in flows:
        print(f"\n=== Flux #{t.get('id')} : {t['sources']} -> {t['destinations']} svc={t['services']} ===")
        rep = check_flow(pano, args.target, t, application=args.app, raw=args.raw)
        for note in rep["notes"]:
            print(f"  [note] {note}")
        for d in rep["details"]:
            print(f"  {d['src']} -> {d['dst']} {d['svc']}  =>  action={d.get('action')}  rule={d.get('rule')}")
        print(f"  => {rep['status']}")
        reports.append(rep)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Rapport -> {args.json_path}")


if __name__ == "__main__":
    main()

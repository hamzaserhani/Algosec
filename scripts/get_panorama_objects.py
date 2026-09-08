"""
Recupere les OBJETS ADRESSES et GROUPES D'ADRESSES depuis Panorama (PAN-OS XML API).

Fait le keygen puis un config-get, parse le XML et exporte en CSV/JSON.

Pourquoi ce script marche la ou les appels manuels echouent :
    - la cle API contient souvent '+', '/', '=' : passee via requests params,
      elle est encodee correctement (pas de "Invalid Credential"). En secours,
      on peut aussi l'envoyer dans le header X-PAN-KEY (--header-key).

Config (config.json, bloc 'panorama') :
    "panorama": {"server": "https://gdcpamgmt002.dir.ucb-group.com",
                 "username": "apisnow", "password": "***", "verify_ssl": false}
    (ou "api_key": "..." au lieu de username/password)

Usage:
    python get_panorama_objects.py                         # shared address + groups
    python get_panorama_objects.py --dg "NewMed - GDC"     # objets d'un device-group
    python get_panorama_objects.py --csv objets.csv --json objets.json
    python get_panorama_objects.py --header-key            # cle en header X-PAN-KEY
"""

import argparse
import csv
import json
import re
from urllib.parse import quote

import requests
import urllib3

DEV = "localhost.localdomain"


def load_panorama_cfg(config_path):
    with open(config_path, "r") as f:
        cfg = json.load(f).get("panorama") or {}
    if not cfg.get("server"):
        raise Exception("Config 'panorama.server' manquante dans config.json")
    return cfg


def keygen(session, server, user, password):
    """Genere la cle API (params encodes par requests)."""
    r = session.get(f"{server}/api/", params={"type": "keygen", "user": user, "password": password})
    r.raise_for_status()
    m = re.search(r"<key>(.*?)</key>", r.text, re.S)
    if not m:
        raise Exception(f"Keygen echoue: {r.text[:300]}")
    return m.group(1).strip()


def config_get(session, server, api_key, xpath, header_key=False):
    """config action=get. Cle via params (encodee) ou header X-PAN-KEY."""
    params = {"type": "config", "action": "get", "xpath": xpath}
    headers = {}
    if header_key:
        headers["X-PAN-KEY"] = api_key
    else:
        params["key"] = api_key
    r = session.get(f"{server}/api/", params=params, headers=headers)
    r.raise_for_status()
    if "status=\"error\"" in r.text or "status = 'error'" in r.text:
        raise Exception(f"Erreur API: {r.text[:300]}")
    return r.text


def parse_addresses(xml):
    """[{name, type, value}] depuis un bloc <address>."""
    out = []
    for name, body in re.findall(r'<entry\s+name="([^"]+)"[^>]*>(.*?)</entry>', xml, re.S):
        nm = re.search(r"<ip-netmask[^>]*>(.*?)</ip-netmask>", body, re.S)
        rg = re.search(r"<ip-range[^>]*>(.*?)</ip-range>", body, re.S)
        fq = re.search(r"<fqdn[^>]*>(.*?)</fqdn>", body, re.S)
        if nm:
            out.append({"name": name, "type": "ip-netmask", "value": nm.group(1).strip()})
        elif rg:
            out.append({"name": name, "type": "ip-range", "value": rg.group(1).strip()})
        elif fq:
            out.append({"name": name, "type": "fqdn", "value": fq.group(1).strip()})
        else:
            out.append({"name": name, "type": "?", "value": ""})
    return out


def parse_groups(xml):
    """[{name, members}] depuis un bloc <address-group> (statiques)."""
    out = []
    for name, body in re.findall(r'<entry\s+name="([^"]+)"[^>]*>(.*?)</entry>', xml, re.S):
        static = re.search(r"<static[^>]*>(.*?)</static>", body, re.S)
        members = []
        if static:
            members = [m.strip() for m in re.findall(r"<member[^>]*>(.*?)</member>", static.group(1), re.S)]
        dyn = re.search(r"<dynamic[^>]*>(.*?)</dynamic>", body, re.S)
        filt = ""
        if dyn:
            fm = re.search(r"<filter[^>]*>(.*?)</filter>", dyn.group(1), re.S)
            filt = fm.group(1).strip() if fm else ""
        out.append({"name": name,
                    "type": "dynamic" if (dyn and not members) else "static",
                    "members": members,
                    "filter": filt})
    return out


def xpaths(dg=None):
    """Retourne (xpath_address, xpath_group) pour shared ou un device-group."""
    if dg:
        base = f"/config/devices/entry[@name='{DEV}']/device-group/entry[@name='{dg}']"
        return base + "/address", base + "/address-group"
    return "/config/shared/address", "/config/shared/address-group"


def main():
    parser = argparse.ArgumentParser(description="Recupere objets adresses + groupes depuis Panorama")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--dg", help="Nom du device-group (sinon shared)")
    parser.add_argument("--csv", dest="csv_path", help="Export CSV des objets adresses")
    parser.add_argument("--json", dest="json_path", help="Export JSON complet (adresses + groupes)")
    parser.add_argument("--header-key", action="store_true", help="Envoyer la cle en header X-PAN-KEY")
    parser.add_argument("--limit", type=int, help="N'afficher que les N premiers (aperçu)")
    args = parser.parse_args()

    cfg = load_panorama_cfg(args.config)
    server = cfg["server"].rstrip("/")
    session = requests.Session()
    session.verify = cfg.get("verify_ssl", True)
    if not session.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    api_key = cfg.get("api_key")
    if not api_key:
        api_key = keygen(session, server, quote(str(cfg["username"])), quote(str(cfg["password"])))
        print("[OK] Cle API obtenue.")

    xp_addr, xp_grp = xpaths(args.dg)
    scope = f"device-group '{args.dg}'" if args.dg else "shared"

    print(f"[...] GET objets adresses ({scope})...")
    addr = parse_addresses(config_get(session, server, api_key, xp_addr, args.header_key))
    print(f"[OK] {len(addr)} objet(s) adresse.")

    print(f"[...] GET groupes d'adresses ({scope})...")
    grp = parse_groups(config_get(session, server, api_key, xp_grp, args.header_key))
    print(f"[OK] {len(grp)} groupe(s).")

    # Apercu console
    print(f"\n--- Adresses (apercu) ---")
    for a in addr[: (args.limit or 10)]:
        print(f"  {a['name']:40} {a['type']:12} {a['value']}")
    print(f"\n--- Groupes (apercu) ---")
    for g in grp[: (args.limit or 10)]:
        print(f"  {g['name']:40} [{g['type']}] {', '.join(g['members'][:5])}"
              + (" ..." if len(g['members']) > 5 else ""))

    if args.csv_path:
        with open(args.csv_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["name", "type", "value"])
            w.writeheader()
            w.writerows(addr)
        print(f"\n[OK] Adresses -> {args.csv_path} ({len(addr)} lignes)")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump({"scope": scope, "addresses": addr, "groups": grp}, f, indent=2, ensure_ascii=False)
        print(f"[OK] JSON complet -> {args.json_path}")


if __name__ == "__main__":
    main()

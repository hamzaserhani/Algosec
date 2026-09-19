"""
Inventaire des interfaces d'un firewall Palo Alto + a qui appartient une IP.

Sert a trancher une question de troubleshooting asymetrie : une IP vue dans un
traceroute (ex: 10.140.0.164) est-elle une interface de CE firewall, ou d'un
AUTRE ? Donne pour chaque interface : IP/mask, VLAN (tag), zone, virtual-router.

    - CAS A : toutes les IP interrogees sont sur CE firewall -> un seul firewall.
    - CAS B : certaines n'y sont pas -> elles sont sur un AUTRE firewall
              (asymetrie inter-firewalls : aller par l'un, retour par l'autre).

Optionnel (--route) : fib-lookup des IP (comment ce firewall les joindrait).

Lecture seule. Usage:
    python interface_check.py --serial GDCFWBCKN001
    python interface_check.py --serial GDCFWBCKN001 --ips 10.140.0.164,10.140.0.10
    python interface_check.py --serial 019909000914 --ips 10.140.0.164 --route --dev
"""

import argparse
import ipaddress
import re

from panorama_client import PanoramaClient


def resolve_serial(pano, value):
    try:
        devices = pano.list_devices()
    except Exception:
        return value
    if value in {d["serial"] for d in devices}:
        return value
    m = [d for d in devices if d.get("hostname", "").lower() == value.lower()]
    if m:
        print(f"[INFO] hostname '{value}' -> serial {m[0]['serial']}")
        return m[0]["serial"]
    return value


def _tag(xml, name):
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)
    return m.group(1).strip() if m else ""


def get_interfaces(pano, serial):
    """Liste des interfaces L3 : name, ip, vlan(tag), zone, vr."""
    xml = pano._op("<show><interface>all</interface></show>", target=serial)
    body = xml
    m = re.search(r"<ifnet>(.*?)</ifnet>", xml, re.S)
    if m:
        body = m.group(1)
    ifaces = []
    for e in re.findall(r"<entry>(.*?)</entry>", body, re.S):
        name = _tag(e, "name")
        ip = _tag(e, "ip")
        if not ip:
            mem = re.search(r"<addr>\s*<member>(.*?)</member>", e, re.S)
            ip = mem.group(1).strip() if mem else ""
        if ip in ("N/A", "n/a"):
            ip = ""
        vr = _tag(e, "fwd")           # ex: "vr:VR-Datacenter" / "tvr:..."
        vr = re.sub(r"^\w+:", "", vr)  # enleve le prefixe vr:/tvr:
        ifaces.append({
            "name": name,
            "ip": ip,
            "vlan": _tag(e, "tag"),
            "zone": _tag(e, "zone"),
            "vr": vr,
        })
    return ifaces


def find_owner(ifaces, target):
    """Interface(s) portant exactement l'IP, ou dont le subnet la contient."""
    t = ipaddress.ip_address(target)
    exact, subnet = [], []
    for i in ifaces:
        if not i["ip"]:
            continue
        try:
            net = ipaddress.ip_interface(i["ip"])
        except ValueError:
            continue
        if net.ip == t:
            exact.append(i)
        elif t in net.network:
            subnet.append(i)
    return exact, subnet


def fib_lookup(pano, serial, vr, ip):
    cmd = (f"<test><routing><fib-lookup><virtual-router>{vr}</virtual-router>"
           f"<ip>{ip}</ip></fib-lookup></routing></test>")
    try:
        x = pano._op(cmd, target=serial)
    except Exception as e:
        return f"erreur: {str(e).splitlines()[0]}"
    iface = _tag(x, "interface")
    nh = _tag(x, "nh") or _tag(x, "nexthop") or _tag(x, "via")
    if not iface and "error" in x.lower():
        msg = re.search(r"<msg>(.*?)</msg>", x, re.S)
        return "pas de route" + (f": {msg.group(1).strip()[:60]}" if msg else "")
    return f"iface={iface or '?'} nexthop={nh or '(direct)'}"


def main():
    p = argparse.ArgumentParser(description="Inventaire interfaces + proprietaire d'une IP (lecture seule)")
    p.add_argument("--serial", help="Serial ou hostname du firewall")
    p.add_argument("--list", action="store_true", help="Lister tous les firewalls connus de Panorama (serial + hostname) puis quitter")
    p.add_argument("--ips", help="IP(s) a localiser (csv), ex: 10.140.0.164,10.140.0.10")
    p.add_argument("--route", action="store_true", help="Ajouter le fib-lookup des IP (comment ce FW les joint)")
    p.add_argument("--filter", dest="flt", help="Ne montrer que les interfaces contenant ce texte (ip/nom)")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")
    pano = PanoramaClient(config_path)
    pano.keygen()

    if args.list:
        print("=" * 60)
        print("[FIREWALLS CONNUS DE PANORAMA]")
        print("=" * 60)
        try:
            devs = pano.list_devices()
        except Exception as e:
            print(f"[ERREUR] list devices : {str(e).splitlines()[0]}")
            return
        for d in sorted(devs, key=lambda x: x.get("hostname", "")):
            print(f"  {d.get('hostname','?'):28} {d['serial']}")
        print(f"\n({len(devs)} firewall(s))")
        return

    if not args.serial:
        print("[!] Fournir --serial (ou --list pour voir les firewalls disponibles).")
        return
    serial = resolve_serial(pano, args.serial)

    print("=" * 74)
    print(f"[INTERFACES] firewall {serial}")
    print("=" * 74)

    try:
        ifaces = get_interfaces(pano, serial)
    except Exception as e:
        print(f"[ERREUR] show interface all : {str(e).splitlines()[0]}")
        return
    if not ifaces:
        print("[!] Aucune interface L3 retournee.")
        return

    shown = ifaces
    if args.flt:
        f = args.flt.lower()
        shown = [i for i in ifaces if f in (i["ip"] + " " + i["name"]).lower()]

    print(f"{'INTERFACE':18} {'IP/MASK':20} {'VLAN':6} {'ZONE':16} VR")
    print("-" * 74)
    for i in sorted(shown, key=lambda x: x["name"]):
        print(f"{i['name']:18} {i['ip'] or '-':20} {i['vlan'] or '-':6} "
              f"{i['zone'] or '-':16} {i['vr'] or '-'}")
    print(f"\n({len(ifaces)} interfaces L3 au total"
          + (f", {len(shown)} affichees apres filtre" if args.flt else "") + ")")

    # --- Localisation des IP demandees ---
    if args.ips:
        targets = [x.strip() for x in args.ips.split(",") if x.strip()]
        print("\n" + "=" * 74)
        print("[LOCALISATION DES IP]")
        print("=" * 74)
        local, absent = [], []
        vrs = list(dict.fromkeys(i["vr"] for i in ifaces if i["vr"]))
        for ip in targets:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"  {ip:16} : IP invalide, ignoree.")
                continue
            exact, subnet = find_owner(ifaces, ip)
            if exact:
                i = exact[0]
                print(f"  {ip:16} : SUR CE FIREWALL  -> interface {i['name']} "
                      f"(IP interface, VLAN {i['vlan'] or '-'}, zone {i['zone'] or '-'}, VR {i['vr'] or '-'})")
                local.append(ip)
            elif subnet:
                i = subnet[0]
                print(f"  {ip:16} : reseau CONNECTE  -> meme subnet que {i['name']} "
                      f"({i['ip']}, VLAN {i['vlan'] or '-'}, zone {i['zone'] or '-'}) "
                      "-> voisin direct (probable interface d'un AUTRE equipement du meme segment)")
                absent.append(ip)
            else:
                print(f"  {ip:16} : PAS sur ce firewall (aucune interface ni subnet local)")
                absent.append(ip)
            if args.route:
                for vr in vrs:
                    r = fib_lookup(pano, serial, vr, ip)
                    if "pas de route" not in r and "erreur" not in r:
                        print(f"                     route (VR {vr}) : {r}")
                        break

        # Verdict cas A / cas B
        if len(targets) >= 2:
            print("\n  >>> VERDICT :")
            if absent and local:
                print(f"      {local} sur CE firewall, mais {absent} N'Y sont PAS.")
                print("      -> CAS B : ces IP sont sur un/des AUTRE(S) firewall(s) -> asymetrie")
                print("         INTER-firewalls (aller par l'un, retour par l'autre).")
            elif not absent:
                print(f"      Toutes les IP ({targets}) sont sur CE firewall.")
                print("      -> CAS A : un seul firewall ; l'asymetrie est au niveau")
                print("         interfaces/fabric (pas inter-boitiers).")
            else:
                print(f"      Aucune de ces IP n'est une interface de CE firewall ({targets}).")
                print("      -> ce sont des interfaces d'un/plusieurs AUTRE(S) equipement(s)")
                print("         (firewall/routeur) sur le chemin. Si --route les montre joignables")
                print("         via nos interfaces, elles sont bien EXTERNES a ce firewall")
                print("         -> autre firewall dans le chemin (candidat asymetrie inter-firewalls).")
    print("=" * 74)


if __name__ == "__main__":
    main()

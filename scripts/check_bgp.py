"""
Diagnostic ROUTAGE / BGP / ECMP d'un firewall Palo Alto : d'ou vient
l'asymetrie (aller sur un chemin, retour sur un autre) ?

Quand le firewall route lui-meme en BGP, l'ECMP vient de routes BGP a
plusieurs next-hops egaux (multipath) et/ou du reglage ECMP du virtual-router.
Si l'ECMP n'est pas symetrique, l'aller et le retour d'un meme flux peuvent
sortir par des interfaces/next-hops differents -> sessions asymetriques ->
drop (flow_tcp_non_syn_drop). Ce script verifie :
    - les virtual-routers du firewall,
    - le reglage ECMP par VR : enable, SYMMETRIC RETURN, max-path, algorithme,
    - l'etat des voisins BGP (summary),
    - [si --src/--dst] les next-hops EFFECTIFS aller et retour (RIB/FIB) ->
      montre concretement si un flux a plusieurs chemins egaux (ECMP).

Lecture seule. Usage :
    python check_bgp.py --serial GDCFWBCKN001
    python check_bgp.py --serial GDCFWBCKN001 --src 10.120.3.26 --dst 10.1.94.89
    python check_bgp.py --serial 019909000914 --dev --dst 10.1.94.89
"""

import argparse
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


def _tags(xml, name):
    return [x.strip() for x in re.findall(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)]


def _tag(xml, name, default=None):
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)
    return m.group(1).strip() if m else default


def list_vrs(pano, serial):
    """Virtual-routers du firewall (via 'show routing summary', fallback config)."""
    try:
        xml = pano._op("<show><routing><summary></summary></routing></show>", target=serial)
        vrs = list(dict.fromkeys(_tags(xml, "virtual-router")))
        vrs = [v for v in vrs if v]
        if vrs:
            return vrs
    except Exception:
        pass
    try:
        cfg = pano.get_config_target(
            "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router", serial)
        return re.findall(r'<entry name="([^"]+)"', cfg)
    except Exception:
        return []


def ecmp_config(pano, serial, vr):
    """Reglage ECMP d'un virtual-router (enable, symmetric-return, max-path, algo)."""
    xpath = (f"/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/"
             f"entry[@name='{vr}']/ecmp")
    try:
        xml = pano.get_config_target(xpath, serial)
    except Exception as e:
        return {"error": str(e).splitlines()[0]}
    enable = (_tag(xml, "enable") or "no").lower()
    sym = (_tag(xml, "symmetric-return") or "no").lower()
    maxp = _tag(xml, "max-path") or _tag(xml, "max-paths") or "?"
    algo_block = re.search(r"<algorithm>(.*?)</algorithm>", xml, re.S)
    algo = "?"
    if algo_block:
        for a in ("ip-modulo", "ip-hash", "weighted-round-robin", "balanced-round-robin"):
            if a in algo_block.group(1):
                algo = a
                break
    return {"enable": enable in ("yes", "true", "1"),
            "symmetric_return": sym in ("yes", "true", "1"),
            "max_path": maxp, "algorithm": algo}


def bgp_summary(pano, serial, vr):
    """Etat des voisins BGP d'un VR."""
    cmd = (f"<show><routing><protocol><bgp><summary>"
           f"<virtual-router>{vr}</virtual-router></summary></bgp></protocol></routing></show>")
    try:
        xml = pano._op(cmd, target=serial)
    except Exception as e:
        return None, str(e).splitlines()[0]
    peers = []
    for entry in re.findall(r"<entry>(.*?)</entry>", xml, re.S):
        peer_ip = _tag(entry, "peer-address") or _tag(entry, "peer-router-id") or _tag(entry, "peer")
        status = _tag(entry, "status") or _tag(entry, "state")
        rib_out = _tag(entry, "installed-routes") or _tag(entry, "accepted-prefixes")
        if peer_ip:
            peers.append((peer_ip, status or "?", rib_out or ""))
    return peers, None


def route_nexthops(pano, serial, vr, ip):
    """Next-hops EFFECTIFS pour une IP (RIB/FIB) -> plusieurs = ECMP."""
    cmd = (f"<show><routing><route><virtual-router>{vr}</virtual-router>"
           f"<destination>{ip}</destination></route></routing></show>")
    try:
        xml = pano._op(cmd, target=serial)
    except Exception as e:
        return None, str(e).splitlines()[0]
    nhs = []
    for entry in re.findall(r"<entry>(.*?)</entry>", xml, re.S):
        dst = _tag(entry, "destination")
        nh = _tag(entry, "nexthop")
        iface = _tag(entry, "interface") or _tag(entry, "nexthop-interface")
        flags = _tag(entry, "flags") or ""
        if nh:
            nhs.append((dst or "?", nh, iface or "?", flags))
    return nhs, None


def main():
    p = argparse.ArgumentParser(description="Diagnostic BGP/ECMP/symetrie de routage (lecture seule)")
    p.add_argument("--serial", required=True, help="Serial ou hostname du firewall")
    p.add_argument("--src", help="IP source du flux (pour voir les next-hops retour)")
    p.add_argument("--dst", help="IP destination du flux (pour voir les next-hops aller)")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")
    pano = PanoramaClient(config_path)
    pano.keygen()
    serial = resolve_serial(pano, args.serial)

    print("=" * 70)
    print(f"[BGP/ECMP] Diagnostic routage du firewall {serial}")
    print("=" * 70)

    vrs = list_vrs(pano, serial)
    if not vrs:
        print("[!] Aucun virtual-router trouve (routage avance/logical-router ? verifier manuellement).")
        return
    print(f"Virtual-routers : {vrs}\n")

    asym_ecmp_vr = []
    for vr in vrs:
        print(f"--- VR '{vr}' " + "-" * (60 - len(vr)))

        # ECMP
        e = ecmp_config(pano, serial, vr)
        if "error" in e:
            print(f"  ECMP : [config illisible] {e['error']}")
        elif not e["enable"]:
            print("  ECMP : DESACTIVE sur ce VR (un seul chemin installe par prefixe).")
        else:
            print(f"  ECMP : ACTIVE  | max-path={e['max_path']}  algorithme={e['algorithm']}")
            if e["symmetric_return"]:
                print("         Symmetric Return = ON  -> le retour ressort par l'interface d'entree "
                      "(aide a la symetrie).")
            else:
                print("         Symmetric Return = OFF  <== l'aller et le retour peuvent sortir par des")
                print("         next-hops DIFFERENTS -> asymetrie possible sur les flux ECMP.")
                asym_ecmp_vr.append(vr)

        # BGP
        peers, err = bgp_summary(pano, serial, vr)
        if err:
            print(f"  BGP  : [pas de summary] {err}")
        elif peers is not None:
            up = sum(1 for _, s, _ in peers if "estab" in s.lower() or "up" in s.lower())
            print(f"  BGP  : {len(peers)} voisin(s), {up} Established")
            for ip, st, rib in peers[:8]:
                print(f"         - {ip:18} {st}" + (f"  routes={rib}" if rib else ""))

        # Next-hops effectifs du flux (ECMP concret)
        for label, ip in (("ALLER  vers dst", args.dst), ("RETOUR vers src", args.src)):
            if not ip:
                continue
            nhs, err = route_nexthops(pano, serial, vr, ip)
            if err:
                print(f"  {label} {ip}: [route illisible] {err}")
            elif not nhs:
                print(f"  {label} {ip}: aucune route (hors de ce VR ?)")
            else:
                tag = "  <== PLUSIEURS next-hops = ECMP" if len(nhs) > 1 else ""
                print(f"  {label} {ip}: {len(nhs)} next-hop(s){tag}")
                for dst, nh, iface, flags in nhs[:6]:
                    print(f"         {dst:20} via {nh:16} {iface}  [{flags}]")
        print()

    # Verdict
    print("=" * 70)
    print(">>> VERDICT :")
    if asym_ecmp_vr:
        print(f"  ECMP ACTIVE sans Symmetric Return sur : {asym_ecmp_vr}")
        print("  -> C'est un moteur d'ASYMETRIE : un flux peut emprunter des next-hops")
        print("     differents a l'aller et au retour. Pistes de correction :")
        print("     1) activer 'Symmetric Return' sur le VR (le retour ressort par l'interface")
        print("        d'entree) — efficace surtout si le serveur est derriere ce firewall ;")
        print("     2) reduire max-path a 1 pour les prefixes concernes (pas d'ECMP = 1 seul chemin),")
        print("        via une route statique/priorite BGP plus specifique (10.1.94.0/23, 10.120.0.0/22) ;")
        print("     3) rendre le hash ECMP coherent aller/retour (algorithme + memes chemins des 2 cotes).")
        print("  NB: si l'asymetrie est INTER-firewalls (plusieurs boitiers annoncent les memes")
        print("      prefixes en BGP), il faut router ces prefixes de facon deterministe vers UN seul.")
    else:
        print("  Pas d'ECMP asymetrique detecte sur les VR lus. Si le flux droppe encore :")
        print("  - verifier si PLUSIEURS firewalls annoncent les memes prefixes BGP (ECMP inter-boitiers),")
        print("  - comparer les next-hops aller/retour ci-dessus (doivent pointer la MEME interface).")
    print("=" * 70)


if __name__ == "__main__":
    main()

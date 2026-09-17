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


def _plausible_vr(name):
    """Filtre les faux 'VR' (noms de route-maps/prefixes remontes par erreur)."""
    if not name:
        return False
    if "/" in name or " " in name:          # prefixes, noms de policy avec espaces
        return False
    if re.match(r"^\d+\.\d+\.\d+", name):     # ressemble a une IP/prefixe
        return False
    return True


def list_vrs(pano, serial):
    """Virtual-routers du firewall (via 'show routing summary', fallback config).
    Filtre le bruit (route-maps/prefixes) pour ne garder que de vrais VR."""
    vrs = []
    try:
        xml = pano._op("<show><routing><summary></summary></routing></show>", target=serial)
        vrs = _tags(xml, "virtual-router")
    except Exception:
        pass
    if not vrs:
        try:
            cfg = pano.get_config_target(
                "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router", serial)
            vrs = re.findall(r'<entry name="([^"]+)"', cfg)
        except Exception:
            vrs = []
    seen, out = set(), []
    for v in vrs:
        v = v.strip()
        if _plausible_vr(v) and v not in seen:
            seen.add(v)
            out.append(v)
    return out


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


def fib_lookup(pano, serial, vr, ip):
    """Chemin EFFECTIF choisi pour une IP (test fib-lookup) -> instantane, 1 resultat.
    Rapide meme avec une RIB enorme (pas de dump de table)."""
    cmd = (f"<test><routing><fib-lookup><virtual-router>{vr}</virtual-router>"
           f"<ip>{ip}</ip></fib-lookup></routing></test>")
    try:
        x = pano._op(cmd, target=serial)
    except Exception as e:
        return None, str(e).splitlines()[0]
    iface = _tag(x, "interface")
    nh = _tag(x, "nh") or _tag(x, "nexthop") or _tag(x, "via")
    dtype = _tag(x, "dtype") or _tag(x, "dm")
    if not iface and "error" in x.lower():
        msg = re.search(r"<msg>(.*?)</msg>", x, re.S)
        return None, ("pas de route: " + (msg.group(1).strip()[:80] if msg else x[:80]))
    return {"iface": iface or "?", "nh": nh or "(direct)", "dtype": dtype or ""}, None


def route_nexthops(pano, serial, vr, ip):
    """[LENT] Dump RIB filtre -> montre TOUS les next-hops egaux (ECMP). Sur --rib."""
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
    p.add_argument("--src", help="IP source du flux (pour voir le chemin retour)")
    p.add_argument("--dst", help="IP destination du flux (pour voir le chemin aller)")
    p.add_argument("--vr", help="Cibler UN seul virtual-router (evite de boucler sur tous)")
    p.add_argument("--no-bgp", action="store_true", help="Ne pas interroger le summary BGP (plus rapide)")
    p.add_argument("--rib", action="store_true",
                   help="[LENT] dump RIB complet du prefixe -> montre TOUS les next-hops ECMP")
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

    vrs = [args.vr] if args.vr else list_vrs(pano, serial)
    if not vrs:
        print("[!] Aucun virtual-router trouve (routage avance/logical-router ? verifier manuellement).")
        return
    print(f"Virtual-routers : {vrs}" + ("  (cible --vr)" if args.vr else "") + "\n")

    # Si un flux est donne, on ne garde que le(s) VR qui RESOLVENT reellement la dst
    # (evite de traiter/afficher les dizaines de VR ou le flux n'existe pas).
    probe_ip = args.dst or args.src
    if probe_ip and not args.vr:
        real = []
        for vr in vrs:
            res, err = fib_lookup(pano, serial, vr, probe_ip)
            if not err and res is not None:
                real.append(vr)
        if real:
            print(f"VR concernes par le flux ({probe_ip}) : {real}\n")
            vrs = real
        else:
            print(f"[!] Aucun VR ne route {probe_ip} — verifier l'IP ou le vsys.\n")

    ecmp_on_vr = []
    skipped = 0
    for vr in vrs:
        # fib-lookup d'abord : si le VR n'existe pas / ne route pas, on saute vite.
        fib = {}
        invalid = False
        for key, ip in (("aller", args.dst), ("retour", args.src)):
            if not ip:
                continue
            res, err = fib_lookup(pano, serial, vr, ip)
            if err and "invalid virtual-router" in (err or "").lower():
                invalid = True
                break
            fib[key] = (res, err)
        if invalid:
            skipped += 1
            continue

        print(f"--- VR '{vr}' " + "-" * max(4, 60 - len(vr)))

        # ECMP
        e = ecmp_config(pano, serial, vr)
        if "error" in e:
            print(f"  ECMP : [config illisible] {e['error']}")
        elif not e["enable"]:
            print("  ECMP : DESACTIVE (un seul chemin installe par prefixe).")
        else:
            print(f"  ECMP : ACTIVE  | max-path={e['max_path']}  algo={e['algorithm']}  "
                  f"Symmetric-Return={'ON' if e['symmetric_return'] else 'OFF'}")
            ecmp_on_vr.append((vr, e["symmetric_return"]))

        # BGP
        if not args.no_bgp:
            peers, err = bgp_summary(pano, serial, vr)
            if err:
                print(f"  BGP  : [pas de summary] {err}")
            elif peers is not None:
                up = sum(1 for _, s, _ in peers if "estab" in s.lower() or "up" in s.lower())
                print(f"  BGP  : {len(peers)} voisin(s), {up} Established")
                for ip, st, rib in peers[:8]:
                    print(f"         - {ip:18} {st}" + (f"  routes={rib}" if rib else ""))

        # Chemin effectif (fib-lookup) : egress vers dst et vers src (informatif)
        for label, key in (("ALLER  vers dst", "aller"), ("RETOUR vers src", "retour")):
            if key not in fib:
                continue
            res, err = fib[key]
            if err or res is None:
                print(f"  {label}: {err or 'pas de resultat'}")
            else:
                print(f"  {label}: egress={res['iface']} nexthop={res['nh']}"
                      + (f" [{res['dtype']}]" if res["dtype"] else ""))
                if args.rib:
                    ip = args.dst if key == "aller" else args.src
                    nhs, rerr = route_nexthops(pano, serial, vr, ip)
                    if not rerr and nhs and len(nhs) > 1:
                        print(f"        RIB: {len(nhs)} next-hops egaux  <== ECMP sur ce prefixe")
                        for d, nh, ifc, fl in nhs[:6]:
                            print(f"           {d:20} via {nh:16} {ifc}  [{fl}]")
        print()

    if skipped:
        print(f"({skipped} VR sans route pour ce flux, ignores)\n")

    # Verdict
    print("=" * 70)
    print(">>> VERDICT :")
    if not ecmp_on_vr:
        print("  ECMP DESACTIVE sur le(s) VR du flux : le firewall installe UN seul chemin")
        print("  par prefixe -> l'asymetrie ne vient PAS d'un multipath du Palo.")
        print("  -> Elle est en AMONT : les routeurs de coeur repartissent (ECMP) l'aller et")
        print("     le retour vers des firewalls/chemins differents (cf. les 2 next-hops")
        print("     10.140.0.x vus au traceroute). C'est LA qu'il faut agir :")
        print("     1) router 10.120.0.0/22 <-> 10.1.94.0/23 de facon DETERMINISTE vers le meme")
        print("        firewall (a l'aller ET au retour), ou hash ECMP symetrique per-flow ;")
        print("     2) mitigation firewall (baisse la secu stateful) : 'set deviceconfig setting")
        print("        tcp asymmetric-path bypass' en attendant le fix routage.")
    else:
        for vr, sr in ecmp_on_vr:
            if not sr:
                print(f"  VR '{vr}': ECMP ACTIVE + Symmetric Return OFF -> moteur d'asymetrie possible.")
                print("     -> activer Symmetric Return, ou max-path 1 sur 10.1.94.0/23 & 10.120.0.0/22.")
            else:
                print(f"  VR '{vr}': ECMP ACTIVE mais Symmetric Return ON -> retour force cote entree.")
    print("=" * 70)


if __name__ == "__main__":
    main()

"""
Diagnostic HA d'un firewall Palo Alto : le cluster est-il capable de gerer le
trafic ASYMETRIQUE (aller sur un membre, retour sur l'autre) sans dropper ?

Contexte : un flux qui passe par une PAIRE de firewalls en ECMP est droppe
(flow_tcp_non_syn_drop) si les 2 membres ne partagent pas leurs sessions. En
active/active, c'est le lien HA3 (packet-forwarding) qui relaie le paquet au
session-owner au lieu de le jeter. Ce script verifie :
    - HA active ? mode active-active / active-passive ?
    - lien HA2 (synchro d'etat/sessions) up + state-sync complete ?
    - lien HA3 (packet-forwarding) configure + up ?  <-- la piece qui manque souvent
    - session-owner-selection / session-setup (first-packet recommande)
    - compteurs d'asymetrie (flow_tcp_non_syn_drop) pour mesurer le probleme

Lecture seule. Usage :
    python check_ha.py --serial GDCFWBCKN001
    python check_ha.py --serial 019909000914 --dev
"""

import argparse
import re

from panorama_client import PanoramaClient


def resolve_serial(pano, value):
    """hostname -> serial vivant (Cloud NGFW autoscale), ou serial tel quel."""
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


def tag(xml, name, default=None):
    """1ere valeur d'une balise <name>...</name> (insensible a la casse)."""
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)
    return m.group(1).strip() if m else default


def section(xml, name):
    """Contenu d'un bloc <name>...</name> (ex: local-info)."""
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)
    return m.group(1) if m else ""


def counter(xml, name):
    m = re.search(rf"<name>{re.escape(name)}</name>\s*.*?<value>(\d+)</value>", xml, re.S)
    if m:
        return int(m.group(1))
    # format alternatif : <entry><name>..</name><value>..</value></entry>
    m = re.search(rf"{re.escape(name)}.*?<value>(\d+)</value>", xml, re.S)
    return int(m.group(1)) if m else None


def main():
    p = argparse.ArgumentParser(description="Diagnostic HA / capacite a gerer l'asymetrie (lecture seule)")
    p.add_argument("--serial", required=True, help="Serial ou hostname du firewall")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")
    pano = PanoramaClient(config_path)
    pano.keygen()
    serial = resolve_serial(pano, args.serial)

    print("=" * 68)
    print(f"[HA] Diagnostic du firewall {serial}")
    print("=" * 68)

    # --- 1. Etat operationnel : show high-availability all ---
    try:
        ha = pano._op("<show><high-availability><all></all></high-availability></show>", target=serial)
    except Exception as e:
        print(f"[ERREUR] show high-availability all : {str(e).splitlines()[0]}")
        return

    enabled = (tag(ha, "enabled", "no") or "no").lower()
    if enabled not in ("yes", "true", "1"):
        print("\n[VERDICT] HA DESACTIVE sur ce firewall.")
        print("  -> Les deux boitiers ne partagent AUCUNE session. L'option 1 (synchro)")
        print("     n'est pas possible tant qu'ils ne sont pas montes en cluster HA.")
        print("  -> Soit former une paire HA active/active (changement lourd, maintenance),")
        print("     soit passer par l'OPTION 2 : rendre l'ECMP symetrique / PBF deterministe.")
        _print_counters(pano, serial)
        _print_toggles(pano, serial)
        return

    local = section(ha, "local-info")
    peer = section(ha, "peer-info")
    mode = (tag(local, "mode") or tag(ha, "mode") or "?").strip()
    local_state = tag(local, "state", "?")
    peer_state = tag(peer, "state", "?")
    peer_conn = tag(peer, "conn-status", tag(peer, "conn-status", "?"))
    peer_serial = tag(peer, "serial-num") or tag(peer, "serial") or "?"
    ha2_state = tag(local, "ha2-state") or tag(ha, "ha2-state")
    state_sync = tag(local, "state-sync") or tag(ha, "state-sync")

    print(f"\n  HA active     : oui")
    print(f"  Mode          : {mode}")
    print(f"  Etat local    : {local_state}    Etat peer : {peer_state} (conn={peer_conn})")
    print(f"  Peer serial   : {peer_serial}")
    print(f"  HA2 (sessions): state={ha2_state or '?'}  state-sync={state_sync or '?'}")

    is_aa = "active-active" in mode.lower() or "active/active" in mode.lower()
    is_ap = "active-passive" in mode.lower() or "active/passive" in mode.lower()

    # --- 2. Config HA (mode active-active, HA3, session-owner/setup) ---
    aa_cfg = ha3_port = so_sel = ss_sel = pkt_fwd = None
    try:
        cfg = pano.get_config_target(
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability", serial)
        aa_cfg = section(cfg, "active-active")
        ha3_port = tag(section(cfg, "ha3") or cfg, "port")
        # session-owner-selection : <first-packet/> ou <primary-device/>
        so_block = section(aa_cfg, "session-owner-selection") if aa_cfg else ""
        so_sel = "first-packet" if "<first-packet" in so_block else (
            "primary-device" if "primary-device" in so_block else None)
        ss_block = section(so_block, "session-setup") if so_block else ""
        if ss_block:
            ss_sel = ("first-packet" if "first-packet" in ss_block else
                      "ip-modulo" if "ip-modulo" in ss_block else
                      "ip-hash" if "ip-hash" in ss_block else
                      "primary-device" if "primary-device" in ss_block else ss_block.strip()[:30])
        pf = tag(aa_cfg, "packet-forwarding") if aa_cfg else None
        pkt_fwd = (pf or "").lower() in ("yes", "true", "1")
    except Exception as e:
        print(f"  [WARN] lecture config HA impossible : {str(e).splitlines()[0]}")

    if ha3_port:
        print(f"  HA3 (pkt-fwd) : interface {ha3_port}")
    print(f"  Packet-forwarding : {'active' if pkt_fwd else ('inactif' if pkt_fwd is not None else '?')}")
    if so_sel:
        print(f"  Session owner : {so_sel}   session setup : {ss_sel or '?'}")

    _print_counters(pano, serial)
    _print_toggles(pano, serial)

    # --- 3. Verdict ---
    print("\n" + "-" * 68)
    print(">>> VERDICT (capacite a gerer l'asymetrie) :")
    if is_ap:
        print("  Mode ACTIVE/PASSIVE.")
        print("  - Pas de HA3/packet-forwarding dans ce mode : le passif ne route pas.")
        print("  - Si du trafic arrive quand meme sur les DEUX (asymetrie), le souci est")
        print("    en AMONT : l'ECMP envoie vers les 2 membres alors qu'un seul est actif.")
        print("  -> FIX : rendre le routage symetrique vers le SEUL actif (OPTION 2),")
        print("     OU basculer en ACTIVE/ACTIVE puis configurer HA3 (voir ci-dessous).")
    elif is_aa:
        ok_ha2 = (ha2_state or "").lower() == "up" and (state_sync or "").lower() in ("complete", "synchronized", "sync")
        ok_ha3 = bool(ha3_port) and pkt_fwd
        print("  Mode ACTIVE/ACTIVE (le bon mode pour l'asymetrie).")
        print(f"  - HA2 synchro sessions : {'OK' if ok_ha2 else 'A VERIFIER (' + str(ha2_state) + '/' + str(state_sync) + ')'}")
        if ok_ha3:
            print("  - HA3 packet-forwarding : CONFIGURE et actif -> le paquet recu par le")
            print("    mauvais membre est RELAYE au session-owner (pas droppe). C'est correct.")
            print("  -> Si le flux droppe encore, verifier : HA3 UP des 2 cotes, bande passante")
            print("     HA3 suffisante, et session-owner-selection = first-packet.")
        else:
            print("  - HA3 packet-forwarding : *** MANQUANT / INACTIF ***  <== LA CAUSE PROBABLE")
            print("  -> C'EST CE QU'IL FAUT ACTIVER :")
            print("     1) dedier une interface type HA (Network > Interfaces),")
            print("     2) Device > HA > HA Communications : Packet Forwarding Link (HA3) = cette interface,")
            print("     3) Device > HA > Active/Active Config : Packet Forwarding = Enabled,")
            print("        Session Owner Selection = First Packet, Session Setup = First Packet,")
            print("     4) commit, puis verifier HA2 + HA3 = Up des deux cotes.")
        if so_sel and so_sel != "first-packet":
            print(f"  - NB: session-owner-selection = {so_sel} (recommande: first-packet).")
    else:
        print(f"  Mode HA non reconnu ('{mode}'). Verifier manuellement : show high-availability all.")
    print("=" * 68)


def _print_counters(pano, serial):
    """Compteurs d'asymetrie -> mesure l'ampleur du probleme."""
    try:
        gc = pano._op("<show><counter><global><filter><aspect>tcp</aspect></filter>"
                      "</global></counter></show>", target=serial)
    except Exception:
        gc = ""
    non_syn = counter(gc, "flow_tcp_non_syn")
    non_syn_drop = counter(gc, "flow_tcp_non_syn_drop")
    oow = counter(gc, "tcp_drop_out_of_wnd")
    if any(v is not None for v in (non_syn, non_syn_drop, oow)):
        print("\n  Compteurs d'asymetrie (indicateurs de drop hors-SYN) :")
        if non_syn is not None:
            print(f"    flow_tcp_non_syn      = {non_syn}")
        if non_syn_drop is not None:
            print(f"    flow_tcp_non_syn_drop = {non_syn_drop}   <- >0 = paquets droppes faute de session")
        if oow is not None:
            print(f"    tcp_drop_out_of_wnd   = {oow}")


def _print_toggles(pano, serial):
    """Etat des contournements d'asymetrie cote firewall (mitigation deja posee ?)."""
    asym = reject = None
    try:
        xml = pano.get_config_target(
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/tcp", serial)
        m = re.search(r"<asymmetric-path>(.*?)</asymmetric-path>", xml)
        asym = m.group(1).strip() if m else "drop (defaut)"
    except Exception:
        pass
    try:
        xml = pano.get_config_target(
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/session", serial)
        m = re.search(r"<tcp-reject-non-syn>(.*?)</tcp-reject-non-syn>", xml)
        reject = m.group(1).strip() if m else "yes (defaut)"
    except Exception:
        pass
    print("\n  Contournements d'asymetrie (etat actuel) :")
    print(f"    tcp asymmetric-path   = {asym or '?'}"
          + ("   -> DROP (aucune tolerance)" if asym and "drop" in asym.lower() else
             "   -> bypass (asymetrie toleree)" if asym and "bypass" in asym.lower() else ""))
    print(f"    tcp-reject-non-syn    = {reject or '?'}"
          + ("   -> rejette les non-SYN (aucune tolerance)" if reject and "yes" in reject.lower() else
             "   -> accepte les non-SYN (tolere)" if reject and "no" in reject.lower() else ""))
    if asym and "drop" in asym.lower():
        print("    (mitigation possible: 'set deviceconfig setting tcp asymmetric-path bypass'"
              " -> baisse la securite TCP stateful)")


if __name__ == "__main__":
    main()

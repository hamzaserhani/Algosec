"""
Troubleshooting d'un flux via les LOGS de trafic Panorama.

On donne source / destination / port / protocole ; le script interroge les logs
(toutes actions), agrege, detecte les anomalies et sort un MINI-RAPPORT avec des
conclusions exploitables : pourquoi un flux ne marche pas, meme s'il est "allowed".

Ce que les logs revelent (au-dela de allow/deny) :
    - session-end-reason : tcp-rst-from-server (serveur refuse), aged-out (pas de
      reponse), tcp-fin (normal), policy-deny, threat...
    - bytes_sent / bytes_received : si allowed mais 0 octet recu -> le serveur ne
      repond pas (port ferme / service down / routing asymetrique) -> PAS le firewall.
    - regle matchee, app, threat, zones.

Usage:
    python analyze_traffic.py --src 10.120.2.10 --dst 10.1.39.11 --port 53 --proto udp
    python analyze_traffic.py --src 10.1.2.3 --dst 8.8.8.8 --port 443 --proto tcp --days 3
    python analyze_traffic.py --src ... --dst ... --port ... --proto tcp --dev --json rep.json
"""

import argparse
import datetime
import json

from panorama_client import PanoramaClient


def build_query(src, dst, port, proto, since_str):
    clauses = [f"(time_generated geq '{since_str}')"]
    if src:
        clauses.append(f"(addr.src in {src})")
    if dst:
        clauses.append(f"(addr.dst in {dst})")
    if port:
        clauses.append(f"(port.dst eq {port})")
    if proto:
        clauses.append(f"(proto eq {proto})")
    return " and ".join(clauses)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def tally(logs, key):
    """Compte les occurrences d'un champ (en tenant compte de repeatcnt)."""
    out = {}
    for e in logs:
        v = e.get(key) or "(vide)"
        out[v] = out.get(v, 0) + max(1, _int(e.get("repeatcnt")))
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# Interpretation des session-end-reason (PAN-OS)
SER_MEANING = {
    "tcp-fin": ("OK", "fermeture TCP normale (le flux fonctionne)"),
    "tcp-rst-from-server": ("PROBLEME", "le SERVEUR a reset la connexion -> port ferme / service down / rejet applicatif (PAS le firewall)"),
    "tcp-rst-from-client": ("INFO", "le CLIENT a reset -> abandon cote client (timeout appli, retry...)"),
    "aged-out": ("SUSPECT", "session expiree sans fermeture propre -> souvent aucune reponse du serveur (one-way) / UDP normal"),
    "policy-deny": ("BLOQUE", "bloque par une regle de securite (deny)"),
    "threat": ("BLOQUE", "bloque par un profil de securite (menace detectee)"),
    "decrypt-cert-validation": ("PROBLEME", "echec validation certificat (dechiffrement SSL)"),
    "decrypt-unsupport-param": ("PROBLEME", "parametres SSL non supportes (dechiffrement)"),
    "tcp-reuse": ("INFO", "reutilisation de session"),
    "n/a": ("INFO", "session non terminee / pas de raison enregistree"),
}


def analyze(logs, flow):
    """Produit le rapport (liste de lignes) + conclusions."""
    report = []
    R = report.append

    total = sum(max(1, _int(e.get("repeatcnt"))) for e in logs)
    R(f"Flux teste : {flow}")
    R(f"Sessions loggees : {total} (sur {len(logs)} entrees)")

    # --- Cas: aucun log ---
    if not logs:
        R("")
        R(">>> CONCLUSION : AUCUN log pour ce flux.")
        R("    - le trafic n'atteint peut-etre pas ce firewall (mauvais chemin / autre FW),")
        R("    - ou aucun trafic n'a ete genere sur la fenetre,")
        R("    - ou la fenetre --days est trop courte. Elargis (--days 7) ou verifie le chemin.")
        return report

    by_action = tally(logs, "action")
    by_rule = tally(logs, "rule")
    by_ser = tally(logs, "session_end_reason")
    by_app = tally(logs, "app")

    R("")
    R(f"Par action        : {by_action}")
    R(f"Par regle         : {by_rule}")
    R(f"Par app           : {by_app}")
    R(f"Session-end-reason: {by_ser}")

    # Bytes (retour serveur)
    tot_sent = sum(_int(e.get("bytes_sent")) for e in logs)
    tot_recv = sum(_int(e.get("bytes_received")) for e in logs)
    R(f"Octets envoyes/recus : {tot_sent} / {tot_recv}")

    # Zones (pour info / chemin)
    zones = tally(logs, "from_zone"), tally(logs, "to_zone")
    R(f"Zones from/to     : {list(zones[0].keys())} -> {list(zones[1].keys())}")

    # Echantillons recents
    R("")
    R("Dernieres sessions :")
    for e in logs[:5]:
        R(f"  {e.get('time')} {e.get('action')} {e.get('src')}->{e.get('dst')}:{e.get('dport')} "
          f"app={e.get('app')} rule={e.get('rule')} end={e.get('session_end_reason')} "
          f"tx/rx={e.get('bytes_sent')}/{e.get('bytes_received')}")

    # --- CONCLUSIONS ---
    R("")
    R(">>> CONCLUSIONS :")
    allow = sum(v for k, v in by_action.items() if k == "allow")
    deny = sum(v for k, v in by_action.items() if k in ("deny", "drop", "reset-both", "reset-client", "reset-server"))

    if deny and not allow:
        R(f"    [BLOQUE] Tout est refuse. Regle(s) deny: {list(by_rule.keys())}.")
        R("             -> il faut une regle d'autorisation (ticket AlgoSec) ou corriger la regle.")
    elif deny and allow:
        R(f"    [PARTIEL] Mix allow ({allow}) / deny ({deny}) -> selon la regle qui matche en premier "
          "(source/port variable ?). Verifie l'ordre des regles et les objets.")
    elif allow:
        R(f"    [AUTORISE] Le firewall laisse passer ({allow} sessions).")
        # Analyse fine des raisons de fin
        for reason, cnt in by_ser.items():
            verdict, expl = SER_MEANING.get(reason.lower(), (None, None)) if reason != "(vide)" else (None, None)
            if verdict and verdict != "OK" and verdict != "INFO":
                R(f"    [{verdict}] session-end-reason '{reason}' ({cnt}) : {expl}")
        # Retour serveur nul
        if allow and tot_recv == 0 and tot_sent > 0:
            R("    [PROBLEME] Trafic autorise mais AUCUN octet recu du serveur (bytes_received=0).")
            R("               -> le serveur ne repond pas : service arrete, mauvais port, ou routing")
            R("                  asymetrique. Ce n'est PAS un blocage firewall. Verifie cote serveur.")
        elif allow and tot_recv > 0:
            R("    [OK] Reponse du serveur presente (bytes_received > 0) -> connectivite bidirectionnelle.")
        # threat
        if "threat" in by_ser:
            R("    [ATTENTION] Des sessions terminees pour 'threat' -> profil de securite bloque le trafic.")

    return report


def main():
    parser = argparse.ArgumentParser(description="Troubleshooting d'un flux via les logs Panorama")
    parser.add_argument("--src", help="IP/subnet source")
    parser.add_argument("--dst", help="IP/subnet destination")
    parser.add_argument("--port", help="Port destination")
    parser.add_argument("--proto", help="Protocole (tcp/udp) ou numero")
    parser.add_argument("--config", help="Fichier de config (defaut: config.json)")
    parser.add_argument("--dev", action="store_true", help="Utiliser config-dev.json")
    parser.add_argument("--days", type=int, default=2, help="Fenetre logs en jours (defaut 2)")
    parser.add_argument("--nlogs", type=int, default=100, help="Nb de logs a analyser (defaut 100)")
    parser.add_argument("--timeout", type=int, default=240, help="Timeout requete log (s)")
    parser.add_argument("--json", dest="json_path", help="Sauve le rapport + logs en JSON")

    args = parser.parse_args()
    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")

    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    since_str = since.strftime("%Y/%m/%d %H:%M:%S")
    query = build_query(args.src, args.dst, args.port, args.proto, since_str)
    flow = f"{args.src or 'any'} -> {args.dst or 'any'} {(args.proto or '')}/{(args.port or 'any')}"

    pano = PanoramaClient(config_path)
    pano.keygen()
    print(f"[...] Recherche logs depuis {since_str}...")
    logs = pano.query_traffic_log(query, nlogs=args.nlogs, max_wait=args.timeout)
    print(f"[OK] {len(logs)} entree(s).\n")

    report = analyze(logs, flow)
    print("=" * 60)
    for line in report:
        print(line)
    print("=" * 60)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump({"flow": flow, "query": query, "report": report, "logs": logs},
                      f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport -> {args.json_path}")


if __name__ == "__main__":
    main()

"""
Diagnostic EXPERT d'un flux - correlation multi-logs Panorama.

A la maniere d'un expert firewall Palo Alto, ce script interroge PLUSIEURS types
de logs pour un flux donne et les CORRELE pour trouver la cause racine :

    - traffic   : passe / bloque, session-end-reason, octets, app, regle
    - threat    : blocage par profil (vulnerability/virus/spyware/dns...)
    - url        : filtrage par categorie d'URL
    - decryption : echecs de dechiffrement SSL (cert, cipher, version TLS)

Il produit un rapport avec des hypotheses de cause racine classees, comme un
vrai troubleshooting expert.

Usage:
    python diagnose_flow.py --src 10.120.2.207 --dst 10.1.39.11 --port 443 --proto tcp
    python diagnose_flow.py --src 10.120.2.207 --url login.microsoftonline.com
    python diagnose_flow.py --src ... --dst ... --port 443 --proto tcp --dev --days 3 --json d.json
"""

import argparse
import datetime
import json
import socket

from panorama_client import PanoramaClient


def resolve_domain(domain):
    """Resout un domaine en liste d'IP (best-effort, stdlib). [] si echec."""
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({str(i[4][0]) for i in infos if ":" not in str(i[4][0])})  # IPv4
        return ips
    except (socket.gaierror, OSError):
        return []


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _is_public(ip):
    """True si l'IP est publique (destination internet)."""
    import ipaddress
    try:
        return not ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _rep(e):
    return max(1, _int(e.get("repeatcnt")))


def tally(logs, *keys):
    """Compte par le 1er champ non vide parmi keys (avec repeatcnt)."""
    out = {}
    for e in logs:
        v = next((e.get(k) for k in keys if e.get(k)), "(vide)")
        out[v] = out.get(v, 0) + _rep(e)
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def build_query(src, dst, port, proto, since_str, by_url=None):
    c = [f"(time_generated geq '{since_str}')"]
    if src:
        c.append(f"(addr.src in {src})")
    if dst:
        c.append(f"(addr.dst in {dst})")
    if port:
        c.append(f"(port.dst eq {port})")
    if proto:
        c.append(f"(proto eq {proto})")
    if by_url:
        c.append(f"(url contains '{by_url}')")
    return " and ".join(c)


# session-end-reason -> (gravite, explication) pour un expert
SER = {
    "tcp-fin": ("OK", "fermeture TCP normale -> le flux fonctionne"),
    "tcp-rst-from-server": ("PROBLEME", "RST du SERVEUR -> port ferme / service down / rejet applicatif (pas le firewall)"),
    "tcp-rst-from-client": ("INFO", "RST du CLIENT -> abandon cote client"),
    "aged-out": ("SUSPECT", "session expiree sans close -> pas de reponse serveur (one-way), ou UDP"),
    "policy-deny": ("BLOQUE", "refuse par une regle de securite"),
    "threat": ("BLOQUE", "bloque par un profil de securite -> voir logs THREAT"),
    "decrypt-cert-validation": ("PROBLEME", "echec validation certificat (SSL decrypt)"),
    "decrypt-unsupport-param": ("PROBLEME", "parametres SSL non supportes (cipher/version) en decrypt"),
    "decrypt-error": ("PROBLEME", "erreur de dechiffrement SSL"),
    "unknown": ("INFO", "raison inconnue"),
}

# app suspectes (handshake incomplet)
APP_SUSPECT = {
    "incomplete": "handshake TCP jamais termine -> le serveur ne repond pas (SYN sans SYN-ACK) ou flux coupe",
    "insufficient-data": "pas assez de donnees pour identifier l'app -> connexion etablie mais peu/pas d'echange applicatif",
    "unknown-tcp": "trafic TCP non identifie par App-ID",
    "unknown-udp": "trafic UDP non identifie",
}


def diagnose_url_only(url_logs, flow, domain):
    """Diagnostic pour un flux par DOMAINE (logs URL uniquement)."""
    R = []
    add = R.append
    add(f"Flux (domaine) : {flow}")
    add(f"Logs URL trouves : {len(url_logs)}")
    add("")
    if not url_logs:
        add(">>> DIAGNOSTIC :")
        add(f"    [INFO] Aucun log URL pour '{domain}'.")
        add("           2 explications probables :")
        add("           1) Les profils URL ne loggent souvent QUE les BLOCAGES, pas les")
        add("              acces autorises -> si le flux passe, il peut ne rien logger ici.")
        add("              => verifie plutot les logs TRAFFIC (ssl vers l'IP) :")
        add(f"                 python scripts/diagnose_flow.py --src <ip> --dst <ip_du_domaine> --port 443 --proto tcp")
        add("           2) Le domaine n'a pas ete visite sur la fenetre (--days), ou nom different.")
        return R
    by_action = tally(url_logs, "action")
    by_cat = tally(url_logs, "category")
    by_rule = tally(url_logs, "rule")
    add(f"[URL] action={by_action} | categorie={by_cat}")
    add(f"      regle={by_rule}")
    add("")
    add("Derniers acces :")
    for e in url_logs[:8]:
        add(f"  {e.get('time_generated')} {e.get('action'):10} -> {e.get('misc') or e.get('url')} "
            f"[cat={e.get('category')}] rule={e.get('rule')}")
    add("")
    add(">>> DIAGNOSTIC :")
    blocked = sum(v for k, v in by_action.items() if "block" in k or k == "deny")
    allowed = sum(v for k, v in by_action.items() if k in ("alert", "allow", "continue"))
    if blocked and not allowed:
        add(f"    [BLOQUE] Acces refuse par filtrage URL. Categorie(s): {list(by_cat.keys())}.")
        add("             -> autoriser la categorie/URL sur la regle, ou whitelister.")
    elif blocked and allowed:
        add(f"    [PARTIEL] Mix autorise ({allowed}) / bloque ({blocked}) selon l'URL exacte.")
    else:
        add(f"    [AUTORISE] Acces web autorise ({allowed}). Categorie(s): {list(by_cat.keys())}.")
    return R


def diagnose(logs_by_type, flow):
    R = []
    add = R.append
    traffic = logs_by_type.get("traffic", []) or []
    threat = logs_by_type.get("threat", []) or []
    url = logs_by_type.get("url", []) or []
    decrypt = logs_by_type.get("decryption", []) or []

    add(f"Flux : {flow}")
    add(f"Logs trouves -> traffic:{len(traffic)}  threat:{len(threat)}  url:{len(url)}  decryption:{len(decrypt)}")
    add("")

    findings = []   # (gravite, titre, detail)

    # ---------- 1. TRAFFIC ----------
    if not traffic:
        findings.append(("INFO", "Aucun log TRAFFIC",
                         "le flux n'atteint peut-etre pas ce firewall (autre chemin), "
                         "ou aucun trafic sur la fenetre (--days), ou mauvais parametres."))
    else:
        by_action = tally(traffic, "action")
        by_rule = tally(traffic, "rule")
        by_app = tally(traffic, "app")
        by_ser = tally(traffic, "session_end_reason", "session-end-reason")
        tx = sum(_int(e.get("bytes_sent")) for e in traffic)
        rx = sum(_int(e.get("bytes_received")) for e in traffic)
        add(f"[TRAFFIC] action={by_action} | app={by_app}")
        add(f"          regle={by_rule}")
        add(f"          session-end={by_ser} | octets tx/rx={tx}/{rx}")

        allow = sum(v for k, v in by_action.items() if k == "allow")
        deny = sum(v for k, v in by_action.items() if k and k != "allow" and k != "(vide)")

        if deny and not allow:
            findings.append(("BLOQUE", "Bloque par la policy (deny)",
                             f"regle(s): {list(by_rule.keys())}. Il faut une regle d'autorisation."))
        elif deny and allow:
            findings.append(("PARTIEL", "Mix allow/deny",
                             f"allow={allow}, deny={deny} -> depend de la regle qui matche (port/source variable)."))

        # apps suspectes
        for app, expl in APP_SUSPECT.items():
            if app in by_app:
                findings.append(("SUSPECT", f"App '{app}' detectee", expl))

        # session-end-reason
        for reason, cnt in by_ser.items():
            sev, expl = SER.get(str(reason).lower(), (None, None))
            if sev and sev not in ("OK", "INFO"):
                findings.append((sev, f"session-end-reason '{reason}' (x{cnt})", expl))

        # retour serveur
        if allow and rx == 0 and tx > 0:
            findings.append(("PROBLEME", "Autorise mais AUCUN retour serveur (rx=0)",
                             "le serveur ne repond pas : service arrete / mauvais port / routing asymetrique. Pas le firewall."))

        # RST client sur (quasi) toutes les sessions
        rst_client = by_ser.get("tcp-rst-from-client", 0)
        dst_public = any(_is_public(e.get("dst")) for e in traffic)
        is_ssl = "ssl" in by_app
        if allow and rst_client and rst_client >= 0.8 * allow:
            if is_ssl and dst_public and rx > 0:
                # Signature classique d'un echec de DECHIFFREMENT SSL sur client non-navigateur
                findings.append(("PROBLEME",
                    f"Probable echec de DECHIFFREMENT SSL ({rst_client}/{allow} sessions en RST client)",
                    "flux SSL sortant, le serveur repond (handshake TCP ok) mais le CLIENT coupe "
                    "systematiquement par RST -> tres probablement le firewall DECHIFFRE le SSL et "
                    "presente son certificat forward-trust ; un client NON-navigateur (SAP, service, "
                    "batch) ne peut pas 'accepter' un certif non fiable et avorte le TLS. "
                    "VERIFIER : (1) ce flux est-il pris par une regle de DECRYPTION ? "
                    "(2) le systeme SAP a-t-il la CA forward-trust du firewall dans son truststore ? "
                    "FIX : exclure cette URL/categorie du dechiffrement (decryption no-decrypt), "
                    "OU installer la CA forward-trust du firewall dans le truststore SAP."))
            else:
                findings.append(("INFO", f"Fermetures par RST client sur ~{rst_client}/{allow} sessions",
                    "le flux passe mais le CLIENT coupe par RST plutot que FIN. Souvent benin "
                    "(keepalive), a surveiller si l'appli signale des coupures/timeouts."))

    # ---------- 2. THREAT ----------
    if threat:
        by_threat = tally(threat, "threatid", "threat_name", "tid")
        by_sev = tally(threat, "severity")
        by_taction = tally(threat, "action")
        add("")
        add(f"[THREAT] menaces={by_threat}")
        add(f"         severite={by_sev} | action={by_taction}")
        blocked = [k for k in by_taction if k in ("reset-both", "reset-client", "reset-server", "drop", "block", "deny", "block-ip")]
        if blocked:
            findings.append(("BLOQUE", "Bloque par un PROFIL DE SECURITE (threat)",
                             f"menace(s): {list(by_threat.keys())}, action: {blocked}. "
                             "-> ajuster le profil (exception/whitelist) ou corriger le trafic."))
        else:
            findings.append(("ATTENTION", "Evenements threat (alert)",
                             f"{list(by_threat.keys())} en alerte (non bloquant), a surveiller."))

    # ---------- 3. URL ----------
    if url:
        by_cat = tally(url, "category")
        by_uaction = tally(url, "action")
        add("")
        add(f"[URL] categorie={by_cat} | action={by_uaction}")
        ublock = [k for k in by_uaction if "block" in k or k in ("deny",)]
        if ublock:
            findings.append(("BLOQUE", "Bloque par FILTRAGE URL",
                             f"categorie(s): {list(by_cat.keys())}, action: {ublock}. "
                             "-> autoriser la categorie/URL ou whitelister."))

    # ---------- 4. DECRYPTION ----------
    if decrypt:
        by_err = tally(decrypt, "error", "err_index")
        by_daction = tally(decrypt, "action")
        add("")
        add(f"[DECRYPTION] erreurs={by_err} | action={by_daction}")
        derr = [k for k in by_err if k and k != "(vide)"]
        if derr:
            findings.append(("PROBLEME", "Echec de DECHIFFREMENT SSL",
                             f"erreur(s): {derr}. -> certificat non fiable, cipher/version TLS non supporte, "
                             "ou epingle (pinning). Exclure l'URL du decrypt, ou corriger le certif."))

    # ---------- SYNTHESE ----------
    add("")
    add("=" * 60)
    add(">>> DIAGNOSTIC EXPERT :")
    severities = {f[0] for f in findings}
    blocking = severities & {"BLOQUE", "PROBLEME", "SUSPECT", "ATTENTION"}
    if not findings:
        if traffic:
            add("    [OK] Aucune anomalie detectee. Le flux fonctionne normalement.")
        else:
            add("    [?] Pas assez de donnees pour conclure (aucun log).")
    else:
        # Si aucune anomalie bloquante (que des INFO) -> le flux fonctionne + notes
        if not blocking and traffic:
            add("    [OK] Le flux fonctionne (serveur repond). Notes ci-dessous :")
        order = {"BLOQUE": 0, "PROBLEME": 1, "SUSPECT": 2, "ATTENTION": 3, "INFO": 4, "OK": 5}
        for sev, titre, detail in sorted(findings, key=lambda f: order.get(f[0], 9)):
            add(f"    [{sev}] {titre}")
            add(f"           {detail}")
    return R


def main():
    p = argparse.ArgumentParser(description="Diagnostic expert d'un flux (correlation multi-logs Panorama)")
    p.add_argument("--src")
    p.add_argument("--dst")
    p.add_argument("--port")
    p.add_argument("--proto")
    p.add_argument("--url", help="Domaine/URL (ajoute le filtre url contains)")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    p.add_argument("--days", type=int, default=2)
    p.add_argument("--nlogs", type=int, default=100)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--json", dest="json_path")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")

    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    since_str = since.strftime("%Y/%m/%d %H:%M:%S")

    flow = f"{args.src or 'any'} -> {args.dst or args.url or 'any'} {(args.proto or '')}/{(args.port or 'any')}"

    pano = PanoramaClient(config_path)
    pano.keygen()
    print(f"[...] Interrogation multi-logs depuis {since_str}...")

    # Mode DOMAINE (--url sans --dst) : les logs traffic ne contiennent pas l'URL
    # -> filtrer le traffic par src seul ramasserait tout (bruit). On se concentre
    # sur les logs URL (la vraie source pour un domaine).
    url_only = bool(args.url) and not args.dst
    if url_only:
        q_url = build_query(args.src, None, None, None, since_str, by_url=args.url)
        specs = [("url", q_url, "url")]
    else:
        q_flow = build_query(args.src, args.dst, args.port, args.proto, since_str)
        q_sec = build_query(args.src, args.dst, None, args.proto, since_str)
        q_url = build_query(args.src, args.dst, None, None, since_str, by_url=args.url)
        specs = [
            ("traffic", q_flow, "traffic"),
            ("threat", q_sec, "threat"),
            ("url", q_url, "url"),
            ("decryption", q_sec, "decryption"),
        ]
    logs = pano.query_logs_parallel(specs, nlogs=args.nlogs, max_wait=args.timeout)
    # Filtre les resultats en erreur (type de log non dispo sur l'instance)
    for k, v in list(logs.items()):
        if isinstance(v, dict) and v.get("_error"):
            print(f"    [WARN] log '{k}' indisponible: {v['_error']}")
            logs[k] = []

    if url_only:
        url_logs = logs.get("url", [])
        report = diagnose_url_only(url_logs, flow, args.url)
        # Pas de log URL (acces autorises souvent non logges) -> on resout le
        # domaine en IP et on analyse les logs TRAFFIC vers ces IP (vrai signal).
        if not url_logs:
            ips = resolve_domain(args.url)
            if ips:
                report.append("")
                report.append(f"[DNS] '{args.url}' resolu en : {', '.join(ips[:8])}"
                              + (f" (+{len(ips)-8})" if len(ips) > 8 else ""))
                report.append("      Analyse des logs TRAFFIC vers ces IP...")
                dst_filter = " or ".join(f"(addr.dst in {ip})" for ip in ips[:8])
                q = f"(time_generated geq '{since_str}')"
                if args.src:
                    q += f" and (addr.src in {args.src})"
                q += f" and ({dst_filter})"
                try:
                    tlogs = pano.query_traffic_log(q, nlogs=args.nlogs, max_wait=args.timeout)
                    report += diagnose({"traffic": tlogs}, f"{flow} (via IP resolues)")
                except Exception as e:
                    report.append(f"      [WARN] requete traffic echouee: {str(e).splitlines()[0]}")
            else:
                report.append("")
                report.append(f"[DNS] Impossible de resoudre '{args.url}' (pas de DNS depuis cette machine).")
    else:
        report = diagnose(logs, flow)
    print("\n" + "=" * 60)
    for line in report:
        print(line)
    print("=" * 60)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump({"flow": flow, "report": report, "logs": logs}, f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport -> {args.json_path}")


if __name__ == "__main__":
    main()

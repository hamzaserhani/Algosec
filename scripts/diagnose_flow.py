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
import re
import socket

from panorama_client import PanoramaClient
from policy_engine import PolicyEngine, _members, _text, VSYS, LOCAL

# Sections de la decryption-rulebase (ordre d'evaluation), via target=serial
DECRYPT_SECTIONS = [
    ("pushed_pre", f"{VSYS}/pre-rulebase/decryption/rules"),
    ("local", f"{LOCAL}/rulebase/decryption/rules"),
    ("pushed_post", f"{VSYS}/post-rulebase/decryption/rules"),
]


def resolve_serial(pano, value):
    """Resout un --serial : si c'est un hostname (ex: pazcweufwp01, Cloud NGFW qui
    auto-scale avec des serials changeants), renvoie un serial VIVANT correspondant.
    Si c'est deja un serial connecte, le renvoie tel quel.
    """
    try:
        devices = pano.list_devices()  # [{serial, hostname}]
    except Exception:
        return value  # pas de resolution possible -> on garde tel quel
    serials = {d["serial"] for d in devices}
    if value in serials:
        return value
    # sinon, cherche par hostname (insensible a la casse)
    matches = [d for d in devices if d.get("hostname", "").lower() == value.lower()]
    if matches:
        chosen = matches[0]["serial"]
        others = [m["serial"] for m in matches[1:]]
        note = f"(hostname '{value}' -> {len(matches)} instance(s) vivante(s), serial retenu: {chosen}"
        note += f"; autres: {others})" if others else ")"
        print(f"[INFO] {note}")
        return chosen
    print(f"[WARN] '{value}' introuvable parmi les firewalls connectes -> utilise tel quel.")
    return value


def check_decryption_rules(pano, serial, src, dst):
    """Verifie si le flux src->dst est pris par une regle de DECHIFFREMENT.

    Retourne (liste de regles matchees [{name,action,type,category}], note).
    Reutilise PolicyEngine pour la resolution d'objets (adresses).
    """
    eng = PolicyEngine(pano, serial)
    eng.load_objects()
    matched = []
    for label, xpath in DECRYPT_SECTIONS:
        try:
            xml = pano.get_config_target(xpath, serial)
        except Exception:
            continue
        for entry in re.findall(r"<entry\b[^>]*>.*?</entry>", xml, re.S):
            name_m = re.search(r'name="([^"]+)"', entry)
            name = name_m.group(1) if name_m else "?"
            if (_text(entry, "disabled") or "no").lower() == "yes":
                continue
            sources = _members(entry, "source")
            dests = _members(entry, "destination")
            cats = _members(entry, "category")
            action = _text(entry, "action") or ""      # decrypt / no-decrypt
            # type : <type><ssl-forward-proxy/></type> ou <type><ssl-inbound-inspection>...
            tmatch = re.search(r"<type>\s*<([\w-]+)", entry)
            rtype = tmatch.group(1) if tmatch else ""
            try:
                if eng._addr_match(sources, src) and eng._addr_match(dests, dst):
                    matched.append({"name": name, "section": label, "action": action,
                                    "type": rtype, "category": cats})
            except Exception:
                continue
    return matched


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


def discover(pano, src, port, since_str, nlogs, timeout):
    """Que contacte reellement cette source ? Top domaines (URL) + top destinations (traffic).

    Sert quand on ne connait pas l'IP/URL exacte vue par le firewall (cloud, geo-DNS).
    """
    R = []
    R.append(f"=== DECOUVERTE : que contacte {src} ? ===")
    base = [f"(time_generated geq '{since_str}')"]
    if src:
        base.append(f"(addr.src in {src})")
    if port:
        base.append(f"(port.dst eq {port})")
    q = " and ".join(base)

    # 1. Domaines via logs URL
    try:
        ulogs = pano.query_url_log(q, nlogs=nlogs, max_wait=timeout)
    except Exception as e:
        ulogs = []
        R.append(f"[URL] erreur: {str(e).splitlines()[0]}")
    if ulogs:
        # top domaines (host de l'url/misc)
        doms = {}
        for e in ulogs:
            u = (e.get("misc") or e.get("url") or "").split("/")[0]
            if u:
                d = doms.setdefault(u, {"n": 0, "act": set()})
                d["n"] += _int(e.get("repeatcnt")) or 1
                if e.get("action"):
                    d["act"].add(e["action"])
        R.append(f"[URL] {len(doms)} domaine(s) contacte(s) (top 15) :")
        for dom, d in sorted(doms.items(), key=lambda kv: -kv[1]["n"])[:15]:
            R.append(f"    {dom:45} {d['n']:4}  {sorted(d['act'])}")
    else:
        R.append("[URL] aucun log URL pour cette source.")

    # 2. Destinations via logs traffic
    try:
        tlogs = pano.query_traffic_log(q, nlogs=nlogs, max_wait=timeout)
    except Exception as e:
        tlogs = []
        R.append(f"[TRAFFIC] erreur: {str(e).splitlines()[0]}")
    if tlogs:
        dsts = {}
        for e in tlogs:
            dip = e.get("dst")
            if dip:
                dd = dsts.setdefault(dip, {"n": 0, "app": set(), "act": set()})
                dd["n"] += _int(e.get("repeatcnt")) or 1
                if e.get("app"):
                    dd["app"].add(e["app"])
                if e.get("action"):
                    dd["act"].add(e["action"])
        R.append(f"[TRAFFIC] {len(dsts)} destination(s) IP (top 15) :")
        reset_ips = []
        for ip, dd in sorted(dsts.items(), key=lambda kv: -kv[1]["n"])[:15]:
            is_reset = any("reset" in a or a in ("deny", "drop") for a in dd["act"])
            flag = "  <-- [!] FIREWALL RESET/DENY" if is_reset else ""
            R.append(f"    {ip:16} {dd['n']:4}  app={sorted(dd['app'])} {sorted(dd['act'])}{flag}")
            if is_reset:
                reset_ips.append(ip)
        if reset_ips:
            R.append("")
            R.append(f">>> [!] {len(reset_ips)} destination(s) COUPEE(S) par le firewall (reset/deny) :")
            R.append(f"        {', '.join(reset_ips)}")
            R.append("        reset-both = le firewall termine activement la session -> profil de")
            R.append("        securite (threat), echec de dechiffrement SSL, ou deny-reset.")
            R.append("        -> analyser en detail chacune :")
            R.append(f"           python scripts/diagnose_flow.py --src {src} --dst {reset_ips[0]} --port {port or 443} --proto tcp --serial <fw>")
    else:
        R.append("[TRAFFIC] aucun log traffic pour cette source.")
    return R


def url_summary(pano, src, domain, since_str, nlogs, timeout):
    """Resume URL pour une source : {rules, categories, actions, count}."""
    c = [f"(time_generated geq '{since_str}')"]
    if src:
        c.append(f"(addr.src in {src})")
    c.append(f"(url contains '{domain}')")
    logs = pano.query_url_log(" and ".join(c), nlogs=nlogs, max_wait=timeout)
    return {
        "count": len(logs),
        "actions": tally(logs, "action"),
        "categories": tally(logs, "category"),
        "rules": tally(logs, "rule"),
        "sample": logs[:3],
    }


def compare_sources(pano, src_ok, src_ko, domain, since_str, nlogs, timeout):
    """Compare deux sources pour un meme domaine (ex: 'marche' vs 'marche pas')."""
    R = []
    R.append(f"=== COMPARAISON pour '{domain}' ===")
    a = url_summary(pano, src_ok, domain, since_str, nlogs, timeout)
    b = url_summary(pano, src_ko, domain, since_str, nlogs, timeout)
    R.append("")
    R.append(f"[SOURCE A] {src_ok}  ({a['count']} logs URL)")
    R.append(f"    action={a['actions']} | categorie={a['categories']}")
    R.append(f"    regle={a['rules']}")
    R.append(f"[SOURCE B] {src_ko}  ({b['count']} logs URL)")
    R.append(f"    action={b['actions']} | categorie={b['categories']}")
    R.append(f"    regle={b['rules']}")
    R.append("")
    R.append(">>> DIFFERENCES :")
    diff = False
    if set(a["rules"]) != set(b["rules"]):
        diff = True
        R.append(f"    [REGLE] A et B ne matchent PAS les memes regles :")
        R.append(f"            A: {list(a['rules'].keys())}")
        R.append(f"            B: {list(b['rules'].keys())}")
        R.append("            -> les deux sources sont traitees par des regles differentes")
        R.append("               (zones/objets source differents) -> profils (decryption, URL,")
        R.append("               security) potentiellement differents. C'est la piste n1.")
    if set(a["categories"]) != set(b["categories"]):
        diff = True
        R.append(f"    [CATEGORIE] categories differentes A={list(a['categories'])} B={list(b['categories'])}")
    if set(a["actions"]) != set(b["actions"]):
        diff = True
        R.append(f"    [ACTION] actions differentes A={list(a['actions'])} B={list(b['actions'])}")
    if b["count"] == 0 and a["count"] > 0:
        diff = True
        R.append(f"    [ABSENCE] Aucun log URL pour B ({src_ko}) -> soit B n'a pas tente,")
        R.append("              soit son trafic ne passe pas par ce firewall / autre chemin.")
    if not diff:
        R.append("    Aucune difference notable cote URL. Si B echoue quand meme, la cause")
        R.append("    est ailleurs (decryption cote B, cert, appli). Comparer les logs TRAFFIC")
        R.append("    des 2 sources (--src B --dst <ip> ... --serial <fw>).")
    return R


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

    # Ventilation PAR IP SOURCE : qui d'autre va vers ce lien, et avec quel verdict ?
    by_src = {}
    for e in url_logs:
        s = e.get("src") or "(vide)"
        d = by_src.setdefault(s, {"n": 0, "actions": set(), "rules": set()})
        d["n"] += _int(e.get("repeatcnt")) or 1
        if e.get("action"):
            d["actions"].add(e["action"])
        if e.get("rule"):
            d["rules"].add(e["rule"])
    if len(by_src) > 1:
        add("")
        add(f"[PAR SOURCE] {len(by_src)} IP source(s) atteignent '{domain}' :")
        for s, d in sorted(by_src.items(), key=lambda kv: -kv[1]["n"]):
            verdict = "BLOQUE" if any("block" in a or a == "deny" for a in d["actions"]) else "autorise"
            add(f"    {s:16} {d['n']:4} acces  [{verdict}]  actions={sorted(d['actions'])} regle={sorted(d['rules'])}")

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
        reset = sum(v for k, v in by_action.items() if "reset" in str(k))
        deny = sum(v for k, v in by_action.items() if k and k != "allow" and k != "(vide)")
        # Indices pour distinguer deny explicite vs reset par profil
        is_policy_deny = "policy-deny" in [str(k).lower() for k in by_ser]
        rules = [str(r) for r in by_rule]
        is_default_rule = any(("default" in r.lower()) for r in rules)  # interzone-default/intrazone-default

        if (deny or reset) and is_policy_deny:
            # session-end = policy-deny -> c'est un DENY de policy (le reset-both n'est
            # que la mecanique du deny), PAS un profil threat/decrypt.
            if is_default_rule:
                findings.append(("BLOQUE",
                    f"AUCUNE regle explicite n'autorise ce flux -> tombe sur '{', '.join(rules)}' (deny par defaut)",
                    "le flux n'est couvert par aucune regle d'autorisation et atteint la regle "
                    "par defaut inter/intra-zone qui le refuse (reset-both). "
                    "-> CREER une regle d'autorisation pour ce flux (ticket AlgoSec), OU si des regles "
                    "d'autorisation existent deja pour ce service, cette DESTINATION n'y est pas couverte "
                    "(IP/SNI absent des objets ou de la categorie URL custom autorisee)."))
            else:
                findings.append(("BLOQUE", f"Bloque par la policy (deny) - regle '{', '.join(rules)}'",
                    "refus explicite par cette regle. Corriger la regle ou creer une autorisation."))
        elif reset:
            # reset sans policy-deny -> vraie piste profil de securite / decrypt
            findings.append(("PROBLEME", f"Firewall RESET la session ({reset} sessions, action reset-*)",
                             "le firewall a etabli puis COUPE activement la connexion sans deny de policy "
                             "explicite -> profil de securite (THREAT) ou echec de DECHIFFREMENT SSL. "
                             "-> voir logs THREAT et DECRYPTION ci-dessous."))
        elif deny and not allow:
            findings.append(("BLOQUE", "Bloque par la policy (deny)",
                             f"regle(s): {rules}. Il faut une regle d'autorisation."))
        elif (deny - reset) > 0 and allow:
            findings.append(("PARTIEL", "Mix allow/deny",
                             f"allow={allow}, deny={deny} -> depend de la regle qui matche (port/source variable)."))

        # apps suspectes
        for app, expl in APP_SUSPECT.items():
            if app in by_app:
                findings.append(("SUSPECT", f"App '{app}' detectee", expl))

        # session-end-reason (policy-deny deja traite ci-dessus -> on l'exclut)
        for reason, cnt in by_ser.items():
            if str(reason).lower() == "policy-deny":
                continue
            sev, expl = SER.get(str(reason).lower(), (None, None))
            if sev and sev not in ("OK", "INFO"):
                findings.append((sev, f"session-end-reason '{reason}' (x{cnt})", expl))

        # retour serveur
        if allow and rx == 0 and tx > 0:
            findings.append(("PROBLEME", "Autorise mais AUCUN retour serveur (rx=0)",
                             "le serveur ne repond pas : service arrete / mauvais port / routing asymetrique. Pas le firewall."))

        # RST client sur (quasi) toutes les sessions -> analyse selon le VOLUME recu.
        # Cle : un echec de dechiffrement/cert coupe des le handshake TLS -> peu
        # d'octets recus (~handshake). Si beaucoup de donnees ont transite, le TLS
        # a reussi -> le RST client est une fermeture applicative (benin).
        rst_client = by_ser.get("tcp-rst-from-client", 0)
        dst_public = any(_is_public(e.get("dst")) for e in traffic)
        is_ssl = "ssl" in by_app
        rx_per_session = rx / allow if allow else 0
        HANDSHAKE_MAX = 6000  # octets : au-dela, des donnees applicatives ont transite
        if allow and rst_client and rst_client >= 0.8 * allow:
            if is_ssl and dst_public and rx_per_session < HANDSHAKE_MAX:
                # Peu d'octets recus + RST systematique -> echec TLS probable (decrypt/cert)
                findings.append(("PROBLEME",
                    f"Probable echec TLS/DECHIFFREMENT ({rst_client}/{allow} RST client, ~{int(rx_per_session)} o/session recus)",
                    "flux SSL sortant coupe par le CLIENT avec TRES PEU de donnees recues "
                    "(~handshake) -> le TLS n'aboutit pas. Cause frequente : le firewall DECHIFFRE "
                    "et presente sa CA forward-trust, qu'un client non-navigateur (SAP/batch) refuse. "
                    "VERIFIER la regle de DECRYPTION (--serial) + la CA dans le truststore SAP. "
                    "FIX : no-decrypt sur l'URL/categorie, ou installer la CA forward-trust."))
            elif is_ssl and dst_public and rx_per_session >= HANDSHAKE_MAX:
                findings.append(("INFO",
                    f"RST client sur {rst_client}/{allow} sessions, mais ~{int(rx_per_session)} o/session recus",
                    "des DONNEES applicatives ont transite -> le TLS a REUSSI, le flux fonctionne. "
                    "Le RST client est une fermeture abrupte (pool de connexions SAP, keepalive). "
                    "Si l'appli signale des erreurs intermittentes, verifier cote applicatif/serveur, "
                    "pas le dechiffrement (qui aurait coupe des le handshake)."))
            else:
                findings.append(("INFO", f"Fermetures par RST client sur ~{rst_client}/{allow} sessions",
                    "le flux passe mais le CLIENT coupe par RST plutot que FIN. Souvent benin."))

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
    p.add_argument("--serial", help="Serial OU hostname du firewall (resolu vers un serial vivant, utile pour Cloud NGFW autoscale) : verifie les regles de DECRYPTION")
    p.add_argument("--vs-src", dest="vs_src", help="2e source a COMPARER pour le meme --url (ex: 'ca marche depuis A, pas depuis B')")
    p.add_argument("--discover", action="store_true", help="Lister ce que --src contacte reellement (domaines URL + destinations IP)")
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

    # Mode DECOUVERTE : que contacte cette source ?
    if args.discover:
        report = discover(pano, args.src, args.port, since_str, args.nlogs, args.timeout)
        print("\n" + "=" * 60)
        for line in report:
            print(line)
        print("=" * 60)
        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump({"report": report}, f, indent=2, ensure_ascii=False)
        return

    # Mode COMPARAISON de 2 sources pour un domaine (ca marche depuis A, pas B)
    if args.vs_src and args.url:
        report = compare_sources(pano, args.src, args.vs_src, args.url, since_str,
                                 args.nlogs, args.timeout)
        print("\n" + "=" * 60)
        for line in report:
            print(line)
        print("=" * 60)
        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump({"report": report}, f, indent=2, ensure_ascii=False)
        return

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
                report.append("      ATTENTION: service potentiellement geo-distribue (cloud) -> ces IP")
                report.append("      peuvent DIFFERER de celles vues par le firewall (+ IPv6 non couvert).")
                report.append("      Les LOGS URL ci-dessus sont la source fiable pour un domaine.")
                report.append("      Analyse des logs TRAFFIC vers ces IP (best-effort)...")
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

    # Confirmation DECRYPTION : si --serial + dst, on verifie la decryption-rulebase
    if args.serial and args.dst:
        serial = resolve_serial(pano, args.serial)  # accepte un hostname (Cloud NGFW autoscale)
        report.append("")
        report.append(f"[DECRYPTION RULES] Verification sur le firewall {serial}...")
        try:
            matched = check_decryption_rules(pano, serial, args.src, args.dst)
            if not matched:
                report.append("    Aucune regle de dechiffrement ne matche ce flux "
                              "-> le flux n'est probablement PAS dechiffre (hypothese decrypt a ecarter).")
            for m in matched:
                act = (m["action"] or m["type"] or "?").lower()
                if "no-decrypt" in act:
                    report.append(f"    [OK] Regle '{m['name']}' -> no-decrypt "
                                  f"(cat={m['category']}) : ce flux N'EST PAS dechiffre.")
                else:
                    report.append(f"    [CONFIRME] Regle '{m['name']}' -> DECRYPT "
                                  f"(type={m['type']}, cat={m['category']}).")
                    report.append("               => le firewall DECHIFFRE ce flux. Si le client SAP ne fait")
                    report.append("                  pas confiance a la CA forward-trust -> echec TLS (RST client).")
                    report.append("               FIX: passer ce flux en 'no-decrypt', ou installer la CA dans SAP.")
        except Exception as e:
            report.append(f"    [WARN] lecture decryption-rulebase echouee: {str(e).splitlines()[0]}")

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

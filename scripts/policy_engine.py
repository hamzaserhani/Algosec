"""
Moteur d'evaluation de policy Palo Alto (cas NO_TRAFFIC / NON_IP).

Evalue si un flux est deja autorise par la POLICY (meme sans trafic), en lisant
les regles shared pre-rulebase et en resolvant les objets a la demande.

Principes (cas courants + flag le reste) :
    - Ignore les regles <disabled>yes</disabled>.
    - SAUTE les regles a categorie URL specifique (<category> != any) : elles ne
      s'appliquent pas a un flux vers une IP interne (corrige le faux 'deny'
      des regles type 'blocking .deepseek.com').
    - Les shared pre-rules sont evaluees en premier : la 1ere qui matche decide.
    - Service 'application-default' -> match non certain -> statut REVIEW.
    - Aucune regle ne matche -> NO_SHARED_MATCH (evaluer les regles device-group,
      non couvert en v1 -> a verifier).

Usage:
    python policy_engine.py config.json --src 10.1.156.5 --dst 10.120.0.10 --svc tcp/50001
    python policy_engine.py config.json --dump-rule "nom de regle"
"""

import argparse
import ipaddress
import re

from panorama_client import PanoramaClient


def _members(block_xml, tag):
    """Extrait les <member> d'un bloc <tag ...>...</tag> (attributs geres)."""
    m = re.search(rf"<{tag}(?:\s[^>]*)?>(.*?)</{tag}>", block_xml, re.S)
    if not m:
        return []
    return [x.strip() for x in re.findall(r"<member(?:\s[^>]*)?>(.*?)</member>", m.group(1), re.S)]


def _text(block_xml, tag):
    """Texte d'une balise <tag ...>...</tag> (attributs geres)."""
    m = re.search(rf"<{tag}(?:\s[^>]*)?>(.*?)</{tag}>", block_xml, re.S)
    return m.group(1).strip() if m else None


# Sections de regles d'un firewall, dans l'ordre d'evaluation PAN-OS.
VSYS = "/config/panorama/vsys/entry[@name='vsys1']"
LOCAL = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
RULE_SECTIONS = [
    ("pushed_pre", f"{VSYS}/pre-rulebase/security/rules"),
    ("local", f"{LOCAL}/rulebase/security/rules"),
    ("pushed_post", f"{VSYS}/post-rulebase/security/rules"),
]
# Emplacements des objets (essayes dans l'ordre, avec target=serial).
ADDR_PATHS = [
    "/config/shared/address/entry[@name='{n}']",
    VSYS + "/address/entry[@name='{n}']",
    LOCAL + "/address/entry[@name='{n}']",
]
ADDRGRP_PATHS = [
    "/config/shared/address-group/entry[@name='{n}']",
    VSYS + "/address-group/entry[@name='{n}']",
]
SVC_PATHS = [
    "/config/shared/service/entry[@name='{n}']",
    VSYS + "/service/entry[@name='{n}']",
]
SVCGRP_PATHS = [
    "/config/shared/service-group/entry[@name='{n}']",
    VSYS + "/service-group/entry[@name='{n}']",
]


class PolicyEngine:
    def __init__(self, pano, serial):
        self.pano = pano
        self.serial = serial     # firewall cible (target)
        self.rules = []          # rulebase effective, dans l'ordre
        self._addr_cache = {}    # name -> list[ip_network] | "any"
        self._svc_cache = {}
        # Tables d'objets chargees en masse (name -> definition brute)
        self._addr_objs = {}     # name -> ("netmask"|"range", valeur)
        self._grp_objs = {}      # name -> [membres]
        self._svc_objs = {}      # name -> [(proto, lo, hi)]

    def _get(self, xpath):
        return self.pano.get_config_target(xpath, self.serial)

    # --- Chargement en masse des objets (rapide : peu d'appels) ---
    def load_objects(self):
        paths_addr = ["/config/shared/address", VSYS + "/address", LOCAL + "/address"]
        paths_grp = ["/config/shared/address-group", VSYS + "/address-group"]
        paths_svc = ["/config/shared/service", VSYS + "/service"]

        for p in paths_addr:
            xml = self._get(p)
            for entry in re.findall(r'<entry\s+name="([^"]+)"[^>]*>(.*?)</entry>', xml, re.S):
                name, body = entry
                if name in self._addr_objs:
                    continue
                nm = _text(body, "ip-netmask")
                rg = _text(body, "ip-range")
                if nm:
                    self._addr_objs[name] = ("netmask", nm)
                elif rg:
                    self._addr_objs[name] = ("range", rg)

        for p in paths_grp:
            xml = self._get(p)
            for entry in re.findall(r'<entry\s+name="([^"]+)"[^>]*>(.*?)</entry>', xml, re.S):
                name, body = entry
                if name not in self._grp_objs:
                    self._grp_objs[name] = _members(body, "static")

        for p in paths_svc:
            xml = self._get(p)
            for entry in re.findall(r'<entry\s+name="([^"]+)"[^>]*>(.*?)</entry>', xml, re.S):
                name, body = entry
                if name in self._svc_objs:
                    continue
                out = []
                for proto in ("tcp", "udp"):
                    m = re.search(rf"<{proto}>(.*?)</{proto}>", body, re.S)
                    if m:
                        port = _text(m.group(1), "port") or ""
                        for part in port.split(","):
                            part = part.strip()
                            if "-" in part:
                                lo, hi = part.split("-", 1)
                                if lo.isdigit() and hi.isdigit():
                                    out.append((proto, int(lo), int(hi)))
                            elif part.isdigit():
                                out.append((proto, int(part), int(part)))
                self._svc_objs[name] = out
        return len(self._addr_objs), len(self._grp_objs), len(self._svc_objs)

    def _first_nonempty(self, paths, name):
        """Renvoie le 1er XML non vide parmi les chemins (formates avec name)."""
        for p in paths:
            xml = self._get(p.format(n=name))
            if re.search(r"<entry\b", xml):
                return xml
        return ""

    # --- Chargement de la rulebase effective du firewall ---
    def load_firewall_rules(self):
        self.rules = []
        for label, xpath in RULE_SECTIONS:
            xml = self._get(xpath)
            for entry in re.findall(r"<entry\b[^>]*>.*?</entry>", xml, re.S):
                name = re.search(r'name="([^"]+)"', entry)
                loc = re.search(r'\bloc="([^"]+)"', entry[:200])
                self.rules.append({
                    "name": name.group(1) if name else "?",
                    "section": label,
                    "loc": loc.group(1) if loc else "?",
                    "disabled": (_text(entry, "disabled") or "no").lower() == "yes",
                    "source": _members(entry, "source"),
                    "destination": _members(entry, "destination"),
                    "service": _members(entry, "service"),
                    "application": _members(entry, "application"),
                    "category": _members(entry, "category"),
                    "action": (_text(entry, "action") or "").lower(),
                })
        return len(self.rules)

    # --- Resolution d'objets (tables en memoire, cache) ---
    def resolve_addr(self, name, _depth=0):
        if name.lower() == "any":
            return "any"
        if name in self._addr_cache:
            return self._addr_cache[name]
        nets = []
        # Litteral IP/subnet ?
        try:
            nets = [ipaddress.ip_network(name, strict=False)]
            self._addr_cache[name] = nets
            return nets
        except ValueError:
            pass
        obj = self._addr_objs.get(name)
        if obj:
            kind, val = obj
            if kind == "netmask":
                try:
                    nets = [ipaddress.ip_network(val, strict=False)]
                except ValueError:
                    nets = []
            elif kind == "range" and "-" in val:
                a, b = val.split("-", 1)
                try:
                    nets = list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())))
                except ValueError:
                    nets = []
        elif name in self._grp_objs and _depth < 10:
            for mem in self._grp_objs[name]:
                r = self.resolve_addr(mem, _depth + 1)
                if r == "any":
                    self._addr_cache[name] = "any"
                    return "any"
                nets.extend(r)
        self._addr_cache[name] = nets
        return nets

    def resolve_svc(self, name):
        low = name.lower()
        if low == "any":
            return "any"
        if low == "application-default":
            return "app-default"
        return self._svc_objs.get(name, [])

    # --- Matching ---
    def _addr_match(self, members, ip):
        addr = ipaddress.ip_address(ip)
        for m in members:
            r = self.resolve_addr(m)
            if r == "any":
                return True
            for net in r:
                if addr in net:
                    return True
        return False

    def _svc_match(self, members, proto, port, ports_only=True):
        """Retourne (match, confident) pour le port.

        - service 'any'            -> match (tout port)
        - service concret couvrant -> match confiant
        - 'application-default'     -> en ports-only : NON match (port inconnu sans
          l'app) ; en mode app-aware : match non confiant.
        """
        for m in members:
            r = self.resolve_svc(m)
            if r == "any":
                return True, True
            if r == "app-default":
                if ports_only:
                    continue  # port indeterminable -> cette regle ne matche pas
                return True, False
            for (p, lo, hi) in r:
                if p == proto and lo <= port <= hi:
                    return True, True
        return False, True

    @staticmethod
    def _app_match(members, flow_app):
        """Retourne (applicable, confident) pour le champ application.

        - regle 'any'                 -> (True, True)   (agnostique de l'app)
        - flow_app connu et dans regle -> (True, True)
        - flow_app connu et absent     -> (False, True) (la regle ne s'applique pas)
        - flow_app inconnu, regle app-specifique -> (True, False) (peut s'appliquer, incertain)
        """
        if not members or members == ["any"]:
            return True, True
        if flow_app:
            return (flow_app.lower() in [m.lower() for m in members]), True
        return True, False

    def evaluate(self, src, dst, proto, port, flow_app=None):
        """Evalue un (src,dst,proto,port[,app]). Retourne dict {status, rule, ...}.

        Mode ports-only (flow_app=None) : on ignore la dimension application et on
        ne matche que sur port concret ; les regles 'application-default' sont
        ignorees. Fournir flow_app active le mode app-aware.
        """
        ports_only = flow_app is None
        for rule in self.rules:
            if rule["disabled"]:
                continue
            # Regle a categorie URL specifique -> ne s'applique pas a un flux IP
            cats = rule["category"]
            if cats and cats != ["any"]:
                continue
            if not self._addr_match(rule["source"], src):
                continue
            if not self._addr_match(rule["destination"], dst):
                continue
            # Application
            apps = rule["application"]
            if ports_only:
                # On ne peut pas evaluer une regle app-specifique sans l'app du
                # flux -> on la SAUTE (evite les faux match type block-teamviewer,
                # block-ms-quick-assist). Seules les regles 'application any'
                # donnent un verdict port-based.
                if apps and apps != ["any"]:
                    continue
                app_confident = True
            else:
                app_ok, app_confident = self._app_match(apps, flow_app)
                if not app_ok:
                    continue
            svc_ok, svc_confident = self._svc_match(rule["service"], proto, port, ports_only)
            if not svc_ok:
                continue
            action = rule["action"]
            confident = app_confident and svc_confident
            status = ("ALLOWED" if action == "allow" else "BLOCKED")
            if not confident:
                status = "REVIEW"
            return {"status": status, "rule": rule["name"], "action": action,
                    "confident": confident, "section": rule.get("section"),
                    "detail": rule,
                    "app_specific": not (not rule["application"] or rule["application"] == ["any"])}
        return {"status": "NO_MATCH", "rule": None, "section": None}


def parse_svc(s):
    m = re.match(r"(tcp|udp)/(\d+)", s.lower())
    if not m:
        raise ValueError(f"service invalide: {s}")
    return m.group(1), int(m.group(2))


def main():
    parser = argparse.ArgumentParser(description="Moteur d'evaluation policy (test unitaire)")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--serial", required=True, help="Serial du firewall a evaluer")
    parser.add_argument("--src", help="IP source")
    parser.add_argument("--dst", help="IP destination")
    parser.add_argument("--svc", help="service tcp/443")
    parser.add_argument("--app", help="App-ID du flux (ex: ssl) - leve l'incertitude sur les regles app-specifiques")
    args = parser.parse_args()

    pano = PanoramaClient(args.config)
    pano.keygen()
    eng = PolicyEngine(pano, args.serial)
    n = eng.load_firewall_rules()
    by_sec = {}
    by_loc = {}
    for r in eng.rules:
        by_sec[r["section"]] = by_sec.get(r["section"], 0) + 1
        by_loc[r.get("loc", "?")] = by_loc.get(r.get("loc", "?"), 0) + 1
    print(f"[OK] {n} regles effectives chargees ({by_sec}).")
    print(f"     par origine (loc): {by_loc}")
    na, ng, ns = eng.load_objects()
    print(f"[OK] objets charges : {na} adresses, {ng} groupes, {ns} services.")

    if args.src and args.dst and args.svc:
        proto, port = parse_svc(args.svc)
        res = eng.evaluate(args.src, args.dst, proto, port, flow_app=args.app)
        print(f"\n{args.src} -> {args.dst} {proto}/{port}" + (f" app={args.app}" if args.app else ""))
        print(f"  => {res['status']}  (regle: {res.get('rule')}, section: {res.get('section')})")
        d = res.get("detail")
        if d:
            print(f"\n  Regle matchee '{d['name']}' :")
            print(f"    source      : {d['source']}")
            print(f"    destination : {d['destination']}")
            print(f"    service     : {d['service']}")
            print(f"    application : {d['application']}")
            print(f"    category    : {d['category']}")
            print(f"    action      : {d['action']}")


if __name__ == "__main__":
    main()

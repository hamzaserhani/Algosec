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
    """Extrait les <member> d'un bloc <tag>...</tag>."""
    m = re.search(rf"<{tag}>(.*?)</{tag}>", block_xml, re.S)
    if not m:
        return []
    return [x.strip() for x in re.findall(r"<member>(.*?)</member>", m.group(1), re.S)]


def _text(block_xml, tag):
    m = re.search(rf"<{tag}>(.*?)</{tag}>", block_xml, re.S)
    return m.group(1).strip() if m else None


class PolicyEngine:
    def __init__(self, pano):
        self.pano = pano
        self.rules = []          # regles shared pre, dans l'ordre
        self._addr_cache = {}    # name -> list[ip_network] | "any"
        self._svc_cache = {}     # name -> list[(proto, lo, hi)] | "any" | "app-default"

    # --- Chargement des regles ---
    def load_shared_pre_rules(self):
        xml = self.pano.get_config("/config/shared/pre-rulebase/security/rules")
        self.rules = []
        for entry in re.findall(r"<entry\b[^>]*>.*?</entry>", xml, re.S):
            name = re.search(r'name="([^"]+)"', entry)
            self.rules.append({
                "name": name.group(1) if name else "?",
                "disabled": (_text(entry, "disabled") or "no").lower() == "yes",
                "source": _members(entry, "source"),
                "destination": _members(entry, "destination"),
                "service": _members(entry, "service"),
                "application": _members(entry, "application"),
                "category": _members(entry, "category"),
                "action": (_text(entry, "action") or "").lower(),
            })
        return len(self.rules)

    # --- Resolution d'objets (a la demande, cache) ---
    def resolve_addr(self, name):
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
        # Objet adresse
        xml = self.pano.get_config(f"/config/shared/address/entry[@name='{name}']")
        netmask = _text(xml, "ip-netmask")
        iprange = _text(xml, "ip-range")
        if netmask:
            try:
                nets = [ipaddress.ip_network(netmask, strict=False)]
            except ValueError:
                nets = []
        elif iprange and "-" in iprange:
            a, b = iprange.split("-", 1)
            try:
                nets = list(ipaddress.summarize_address_range(
                    ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())))
            except ValueError:
                nets = []
        else:
            # Groupe d'adresses (membres statiques) ?
            gxml = self.pano.get_config(f"/config/shared/address-group/entry[@name='{name}']")
            members = _members(gxml, "static")
            for mem in members:
                r = self.resolve_addr(mem)
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
        if name in self._svc_cache:
            return self._svc_cache[name]
        out = []
        xml = self.pano.get_config(f"/config/shared/service/entry[@name='{name}']")
        for proto in ("tcp", "udp"):
            m = re.search(rf"<{proto}>(.*?)</{proto}>", xml, re.S)
            if m:
                port = _text(m.group(1), "port") or ""
                for part in port.split(","):
                    part = part.strip()
                    if "-" in part:
                        lo, hi = part.split("-", 1)
                        out.append((proto, int(lo), int(hi)))
                    elif part.isdigit():
                        out.append((proto, int(part), int(part)))
        if not out:
            # service-group ?
            gxml = self.pano.get_config(f"/config/shared/service-group/entry[@name='{name}']")
            for mem in _members(gxml, "members"):
                r = self.resolve_svc(mem)
                if r in ("any", "app-default"):
                    self._svc_cache[name] = r
                    return r
                out.extend(r)
        self._svc_cache[name] = out
        return out

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

    def _svc_match(self, members, proto, port):
        """Retourne (match, confident)."""
        for m in members:
            r = self.resolve_svc(m)
            if r == "any":
                return True, True
            if r == "app-default":
                return True, False  # match mais port non certain
            for (p, lo, hi) in r:
                if p == proto and lo <= port <= hi:
                    return True, True
        return False, True

    def evaluate(self, src, dst, proto, port):
        """Evalue un (src,dst,proto,port). Retourne dict {status, rule, ...}."""
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
            svc_ok, confident = self._svc_match(rule["service"], proto, port)
            if not svc_ok:
                continue
            action = rule["action"]
            status = ("ALLOWED" if action == "allow" else "BLOCKED")
            if not confident:
                status = "REVIEW"
            return {"status": status, "rule": rule["name"], "action": action,
                    "confident": confident}
        return {"status": "NO_SHARED_MATCH", "rule": None}


def parse_svc(s):
    m = re.match(r"(tcp|udp)/(\d+)", s.lower())
    if not m:
        raise ValueError(f"service invalide: {s}")
    return m.group(1), int(m.group(2))


def main():
    parser = argparse.ArgumentParser(description="Moteur d'evaluation policy (test unitaire)")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--src", help="IP source")
    parser.add_argument("--dst", help="IP destination")
    parser.add_argument("--svc", help="service tcp/443")
    args = parser.parse_args()

    pano = PanoramaClient(args.config)
    pano.keygen()
    eng = PolicyEngine(pano)
    n = eng.load_shared_pre_rules()
    print(f"[OK] {n} regles shared pre chargees.")

    if args.src and args.dst and args.svc:
        proto, port = parse_svc(args.svc)
        res = eng.evaluate(args.src, args.dst, proto, port)
        print(f"\n{args.src} -> {args.dst} {proto}/{port}")
        print(f"  => {res['status']}  (regle: {res.get('rule')})")


if __name__ == "__main__":
    main()

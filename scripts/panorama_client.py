"""
Client Panorama (PAN-OS XML API) - test security-policy-match.

Sert a savoir si un flux est reellement autorise sur un firewall Palo Alto
(verdict live, App-ID aware), via une commande operationnelle redirigee par
Panorama vers un firewall cible (target=<serial>).

API PAN-OS :
    - Keygen : GET  /api/?type=keygen&user=<u>&password=<p>  -> <key>...</key>
    - Op cmd : GET  /api/?type=op&cmd=<...>&target=<serial>&key=<key>
    - Devices: <show><devices><connected></connected></devices></show>
    - Match  : <test><security-policy-match>
                 <source>IP</source><destination>IP</destination>
                 <destination-port>N</destination-port><protocol>6|17</protocol>
                 [<application>app</application>]
               </security-policy-match></test>
      -> destination-port et protocol : ENTIERS UNIQUES (pas de 'any'/plage).

Config (config.json) :
    "panorama": {
        "server": "https://panorama.example.com",
        "api_key": "...",              // ou username/password
        "username": "...", "password": "...",
        "verify_ssl": false
    }
"""

import json
import os
import re
import time
from urllib.parse import quote

import requests
import urllib3

PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1"}


class PanoramaClient:
    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            cfg = json.load(f).get("panorama") or {}
        if not cfg.get("server"):
            raise Exception("Config 'panorama.server' manquante dans config.json")

        self.server = cfg["server"].rstrip("/")
        self.api_key = cfg.get("api_key")
        self.username = cfg.get("username")
        self.password = cfg.get("password")
        self.verify_ssl = cfg.get("verify_ssl", True)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.debug = os.environ.get("ALGOSEC_DEBUG", "").lower() in ("1", "true", "yes")
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def keygen(self):
        """Genere une cle API a partir de username/password (si pas d'api_key)."""
        if self.api_key:
            return self.api_key
        if not (self.username and self.password):
            raise Exception("Panorama: fournir 'api_key' OU 'username'+'password' dans config.json")
        url = (f"{self.server}/api/?type=keygen&user={quote(str(self.username))}"
               f"&password={quote(str(self.password))}")
        resp = self.session.get(url)
        resp.raise_for_status()
        m = re.search(r"<key>(.*?)</key>", resp.text, re.S)
        if not m:
            raise Exception(f"Keygen Panorama echoue: {resp.text[:300]}")
        self.api_key = m.group(1).strip()
        print("[OK] Cle API Panorama obtenue.")
        return self.api_key

    def _op(self, cmd_xml, target=None):
        """Execute une commande operationnelle. Retourne le texte XML brut."""
        if not self.api_key:
            self.keygen()
        params = {"type": "op", "cmd": cmd_xml, "key": self.api_key}
        if target:
            params["target"] = target
        if self.debug:
            print(f"[DEBUG] Panorama op target={target} cmd={cmd_xml[:200]}")
        resp = self.session.get(f"{self.server}/api/", params=params)
        resp.raise_for_status()
        return resp.text

    def list_devices(self):
        """Liste les firewalls connectes : [{serial, hostname}]."""
        xml = self._op("<show><devices><connected></connected></devices></show>")
        devices = []
        for entry in re.findall(r"<entry[^>]*>(.*?)</entry>", xml, re.S):
            serial = re.search(r"<serial>(.*?)</serial>", entry, re.S)
            host = re.search(r"<hostname>(.*?)</hostname>", entry, re.S)
            if serial:
                devices.append({
                    "serial": serial.group(1).strip(),
                    "hostname": host.group(1).strip() if host else "",
                })
        return devices

    def get_config(self, xpath):
        """Recupere une portion de config (type=config&action=get). Retourne le XML."""
        if not self.api_key:
            self.keygen()
        params = {"type": "config", "action": "get", "xpath": xpath, "key": self.api_key}
        if self.debug:
            print(f"[DEBUG] Panorama get-config xpath={xpath[:160]}")
        resp = self.session.get(f"{self.server}/api/", params=params)
        resp.raise_for_status()
        return resp.text

    def find_device_group(self, hostname_or_serial):
        """Retourne le nom du device-group contenant ce firewall (ou None).

        Parcourt 'show devicegroups' et cherche le hostname/serial dans chaque DG.
        """
        xml = self._op("<show><devicegroups></devicegroups></show>")
        target = hostname_or_serial.lower()
        # Decoupe par device-group de 1er niveau : <entry name="DG"> ... jusqu'au prochain
        for m in re.finditer(r'<entry name="([^"]+)">(.*?)(?=<entry name="[^"]+">\s*<devices>|</devicegroups>)',
                             xml, re.S):
            name, body = m.group(1), m.group(2)
            if "<devices>" not in body:
                continue
            if target in body.lower():
                return name
        return None

    def submit_log_job(self, query, nlogs=20):
        """Soumet une requete log et retourne le job id (asynchrone)."""
        if not self.api_key:
            self.keygen()
        params = {"type": "log", "log-type": "traffic", "query": query,
                  "nlogs": str(nlogs), "key": self.api_key}
        if self.debug:
            print(f"[DEBUG] Panorama log query: {query[:250]}")
        resp = self.session.get(f"{self.server}/api/", params=params)
        resp.raise_for_status()
        job = re.search(r"<job>(\d+)</job>", resp.text)
        if not job:
            raise Exception(f"Log query : pas de job id. Reponse: {resp.text[:300]}")
        return job.group(1)

    def fetch_log_job(self, job_id, max_wait=60, poll=1.0):
        """Poll un job log jusqu'a FIN et retourne les entrees."""
        waited = 0.0
        while waited < max_wait:
            r = self.session.get(f"{self.server}/api/", params={
                "type": "log", "action": "get", "job-id": job_id, "key": self.api_key})
            r.raise_for_status()
            status = re.search(r"<status>(\w+)</status>", r.text)
            if status and status.group(1).upper() in ("FIN", "FINISHED"):
                return self._parse_log_entries(r.text)
            time.sleep(poll)
            waited += poll
        raise Exception(f"Log query timeout ({max_wait}s) pour job {job_id}")

    def query_traffic_log(self, query, nlogs=20, max_wait=60, poll=1.0):
        """Requete log (submit + poll). Voir submit_log_job/fetch_log_job pour paralleliser."""
        job_id = self.submit_log_job(query, nlogs)
        return self.fetch_log_job(job_id, max_wait=max_wait, poll=poll)

    def query_traffic_logs_parallel(self, queries, nlogs=20, max_wait=60, poll=1.0):
        """Soumet plusieurs requetes d'un coup puis poll toutes -> divise l'attente.

        queries : liste de filtres. Retourne une liste de listes d'entrees (meme ordre).
        """
        job_ids = [self.submit_log_job(q, nlogs) for q in queries]
        return [self.fetch_log_job(jid, max_wait=max_wait, poll=poll) for jid in job_ids]

    @staticmethod
    def _parse_log_entries(xml):
        """Parse les <entry> d'une reponse log en dicts."""
        entries = []
        for body in re.findall(r"<entry[^>]*>(.*?)</entry>", xml, re.S):
            def g(tag):
                m = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.S)
                return m.group(1).strip() if m else None
            entries.append({
                "action": g("action"), "src": g("src"), "dst": g("dst"),
                "dport": g("dport"), "rule": g("rule"), "time": g("time_generated"),
                "app": g("app"),
            })
        return entries

    def test_policy_match(self, serial, source, destination, dport, protocol,
                          application=None, from_zone=None, to_zone=None):
        """test security-policy-match sur un firewall cible. Retourne (rule, action, raw).

        dport : entier ; protocol : 'tcp'/'udp' ou numero. Pas de plage/any.
        """
        proto = PROTO_NUM.get(str(protocol).lower(), str(protocol))
        parts = [
            f"<source>{source}</source>",
            f"<destination>{destination}</destination>",
            f"<destination-port>{dport}</destination-port>",
            f"<protocol>{proto}</protocol>",
        ]
        if application:
            parts.append(f"<application>{application}</application>")
        if from_zone:
            parts.append(f"<from>{from_zone}</from>")
        if to_zone:
            parts.append(f"<to>{to_zone}</to>")
        cmd = f"<test><security-policy-match>{''.join(parts)}</security-policy-match></test>"

        raw = self._op(cmd, target=serial)
        # Parsing best-effort : nom de regle + action
        rule = re.search(r'<rules?>.*?<entry name="(.*?)"', raw, re.S) or \
               re.search(r"<name>(.*?)</name>", raw, re.S)
        action = re.search(r"<action>(.*?)</action>", raw, re.S)
        rule_name = rule.group(1).strip() if rule else None
        action_val = action.group(1).strip() if action else None
        return rule_name, action_val, raw


if __name__ == "__main__":
    import sys
    c = PanoramaClient(sys.argv[1] if len(sys.argv) > 1 else "config.json")
    c.keygen()
    if len(sys.argv) >= 2 and sys.argv[-1] == "--devices":
        for d in c.list_devices():
            print(f"  {d['serial']}  {d['hostname']}")
    # Test : python panorama_client.py config.json <serial> <src> <dst> <dport> <tcp|udp> [app]
    elif len(sys.argv) >= 7:
        serial, src, dst, dport, proto = sys.argv[2:7]
        app = sys.argv[7] if len(sys.argv) > 7 else None
        rule, action, raw = c.test_policy_match(serial, src, dst, dport, proto, app)
        print(f"rule={rule}  action={action}")
        print(raw)

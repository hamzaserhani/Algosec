"""
Client AlgoSec Firewall Analyzer (AFA) - Traffic Simulation Query.

Sert a savoir si un flux est DEJA autorise sur les firewalls (auto-path), avant
de creer une demande FireFlow. Lecture seule : la query ne modifie rien.

API (differente de FireFlow) :
    - Login : POST {server}/fa/server/connection/login  {"username","password"}
              -> {"status": true, "SessionID": "..."}
    - Query : POST {server}/afa/api/v1/query  (cookie PHPSESSID=<SessionID>)
              body: {"queryInput":[{"source":[...],"destination":[...],
                     "service":[...],"user":["any"],"application":["any"]}],
                     "queryTarget":"ALL_FIREWALLS","includeDevicesPaths":true}

Config (config.json) : reutilise server / username / password / verify_ssl.
Surcharges optionnelles : afa_username, afa_password, query_target.
"""

import json
import os

import requests
import urllib3


class AfaClient:
    """Client REST pour l'API AFA (traffic simulation query)."""

    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            config = json.load(f)

        self.server = config["server"].rstrip("/")
        # Memes identifiants que FireFlow par defaut (surchargeables).
        self.username = config.get("afa_username") or config["username"]
        self.password = config.get("afa_password") or config["password"]
        self.verify_ssl = config.get("verify_ssl", True)
        # Cible de la query : "ALL_FIREWALLS" (tout le reseau) par defaut.
        self.query_target = config.get("query_target", "ALL_FIREWALLS")

        self.login_url = f"{self.server}/fa/server/connection/login"
        self.query_url = f"{self.server}/afa/api/v1/query"

        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session_id = None
        self.debug = os.environ.get("ALGOSEC_DEBUG", "").lower() in ("1", "true", "yes")

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self):
        """Authentification AFA, capture du SessionID (cookie PHPSESSID)."""
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = self.session.post(self.login_url, json=payload, headers=headers)
        if self.debug:
            print(f"[DEBUG] AFA login {self.login_url} -> {resp.status_code}")
        resp.raise_for_status()

        data = resp.json()
        # Le champ peut s'appeler SessionID / sessionId selon la version.
        sid = data.get("SessionID") or data.get("sessionId") or data.get("sessionID")
        if not data.get("status", True) or not sid:
            raise Exception(f"Echec login AFA: {json.dumps(data)[:300]}")

        self.session_id = sid
        # Cookie PHPSESSID requis pour /afa/api/v1
        self.session.cookies.set("PHPSESSID", sid)
        print(f"[OK] AFA login reussi. SessionID: {sid[:8]}...")
        return sid

    def query(self, sources, destinations, services, user="any", application="any"):
        """Lance une traffic simulation query. Retourne le JSON brut de la reponse."""
        if not self.session_id:
            raise Exception("Non authentifie. Appelez login() d'abord.")

        body = {
            "queryInput": [{
                "source": list(sources),
                "destination": list(destinations),
                "service": list(services) if services else ["any"],
                "user": [user],
                "application": [application],
            }],
            "queryTarget": self.query_target,
            "includeDevicesPaths": True,
            "includeRulesZones": False,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.debug:
            print(f"[DEBUG] AFA query body: {json.dumps(body)[:300]}")
        resp = self.session.post(self.query_url, json=body, headers=headers)
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            body_txt = ""
            try:
                body_txt = json.dumps(resp.json(), ensure_ascii=False)[:1000]
            except Exception:
                body_txt = (resp.text or "")[:1000]
            raise requests.HTTPError(
                f"AFA query -> {resp.status_code}\n{body_txt}", response=resp
            )
        return resp.json()


if __name__ == "__main__":
    import sys
    c = AfaClient(sys.argv[1] if len(sys.argv) > 1 else "config.json")
    c.login()
    # Test rapide : python afa_client.py config.json "10.0.0.1" "192.168.1.1" "tcp/443"
    if len(sys.argv) >= 5:
        result = c.query([sys.argv[2]], [sys.argv[3]], [sys.argv[4]])
        print(json.dumps(result, indent=2, ensure_ascii=False))

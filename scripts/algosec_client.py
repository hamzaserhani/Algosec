"""
Client AlgoSec FireFlow - Authentification et gestion de session.
"""

import json
import os
import requests
import urllib3


class AlgosecClient:
    """Client pour interagir avec l'API REST FireFlow d'AlgoSec."""

    # Noms de cookies candidats selon les versions de FireFlow (fallback uniquement)
    COOKIE_CANDIDATES = ("FireFlow_Session", "JSESSIONID", "fireflowSessionId", "FF_SESSION")

    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            config = json.load(f)

        self.server = config["server"].rstrip("/")
        # Path API FireFlow. Selon la version : "/FireFlow/api" (ancien) ou "/aff/api/external" (recent).
        # Si non specifie, on commence avec "/FireFlow/api" et on auto-aligne sur le Path du cookie d'auth.
        self.api_path = config.get("api_path", "/FireFlow/api")
        self.base_url = self.server + self.api_path
        self.username = config["username"]
        self.password = config["password"]
        # Domain FireFlow (souvent "0" pour le domaine par defaut)
        self.domain = str(config.get("domain", "0"))
        self.verify_ssl = config.get("verify_ssl", True)
        self.session_id = None
        # Cookies captures depuis la reponse d'auth, envoyes manuellement sur chaque appel
        # (on ne se fie pas au cookie jar pour eviter les soucis de scoping Path/Domain).
        self.cookies = {}
        # Active la log des requetes via env var ALGOSEC_DEBUG=1
        self.debug = os.environ.get("ALGOSEC_DEBUG", "").lower() in ("1", "true", "yes")

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def authenticate(self):
        """Authentification, capture du sessionId et des cookies de la reponse."""
        url = f"{self.base_url}/authentication/authenticate"
        payload = {
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        response = requests.post(
            url, json=payload, headers=headers, verify=self.verify_ssl
        )
        response.raise_for_status()

        data = response.json()
        if data.get("status") != "Success":
            messages = data.get("messages", [])
            error_msg = messages[0]["message"] if messages else "Erreur inconnue"
            raise Exception(f"Echec authentification: {error_msg}")

        self.session_id = data["data"]["sessionId"]

        # Capture tous les cookies poses par le serveur (sans tenir compte du Path/Domain)
        cookie_paths = set()
        for c in response.cookies:
            self.cookies[c.name] = c.value
            if c.path:
                cookie_paths.add(c.path)

        # Fallback : si aucun cookie pose, on essaie les noms standards avec le sessionId JSON
        if not self.cookies:
            for name in self.COOKIE_CANDIDATES:
                self.cookies[name] = self.session_id

        cookie_summary = ", ".join(f"{n}={v[:8]}..." for n, v in self.cookies.items())
        print(f"[OK] Authentification reussie. Session ID: {self.session_id[:8]}... | Cookies: {cookie_summary}")

        if self.debug:
            print(f"[DEBUG] Set-Cookie headers bruts: {response.headers.get('Set-Cookie')}")

        # Auto-aligne le base_url sur le Path du cookie si different.
        # Exemple : auth a /FireFlow/api mais cookie scope sur /aff/api/external -> on bascule.
        if cookie_paths:
            most_specific = sorted(cookie_paths, key=len, reverse=True)[0]
            if not self.api_path.rstrip("/").endswith(most_specific.rstrip("/")):
                old = self.base_url
                self.api_path = most_specific
                self.base_url = self.server + self.api_path
                print(f"[INFO] Path API auto-aligne sur le cookie: {old} -> {self.base_url}")

        return self.session_id

    def _ensure_authenticated(self):
        if not self.session_id:
            raise Exception("Non authentifie. Appelez authenticate() d'abord.")

    def _build_cookie_header(self):
        """Construit le header Cookie a partir des cookies captures."""
        return "; ".join(f"{name}={value}" for name, value in self.cookies.items())

    def _get_headers(self):
        """Headers communs : JSON + cookie de session manuel."""
        self._ensure_authenticated()
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cookie": self._build_cookie_header(),
        }

    def _raise_with_body(self, response, method, url):
        """Raise HTTPError en incluant le body de la reponse pour le diagnostic."""
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            body = ""
            try:
                body = json.dumps(response.json(), indent=2, ensure_ascii=False)
            except Exception:
                body = response.text[:2000]
            raise requests.HTTPError(
                f"{method} {url} -> {response.status_code}\n--- Response body ---\n{body}",
                response=response,
            ) from e

    def _log_debug(self, method, url, headers, payload=None):
        if not self.debug:
            return
        safe_headers = {k: (v[:30] + "..." if k == "Cookie" and len(v) > 30 else v) for k, v in headers.items()}
        print(f"[DEBUG] {method} {url}")
        print(f"[DEBUG]   headers: {safe_headers}")
        if payload is not None:
            print(f"[DEBUG]   body: {json.dumps(payload)[:300]}")

    def post(self, endpoint, payload):
        """Effectue un POST authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        self._log_debug("POST", url, headers, payload)
        response = requests.post(url, json=payload, headers=headers, verify=self.verify_ssl)
        self._raise_with_body(response, "POST", url)
        return response.json()

    def get(self, endpoint):
        """Effectue un GET authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        self._log_debug("GET", url, headers)
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        self._raise_with_body(response, "GET", url)
        return response.json()


if __name__ == "__main__":
    client = AlgosecClient()
    client.authenticate()

"""
Client AlgoSec FireFlow - Authentification et gestion de session.
"""

import json
import os
from urllib.parse import urlparse

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
        # Template FireFlow par defaut pour la creation de tickets (optionnel).
        # Peut etre surcharge en CLI. Si absent -> "Basic Change Traffic Request".
        self.default_template = config.get("template") or "Basic Change Traffic Request"
        # Utilisateur par defaut pour la ligne de trafic (requis si l'option
        # FireFlow ShowUserFieldInCreateForm est activee). Defaut -> "any".
        self.default_user = config.get("user") or "any"
        # Champs personnalises obligatoires du template AU NIVEAU TICKET
        # (ex: MSI code, Permanent). Envoyes avec la cle "key".
        # Format config.json: {"fields": {"MSI code": "...", "Permanent": "Yes"}}
        self.custom_fields = config.get("fields") or {}
        # Champs personnalises AU NIVEAU LIGNE DE TRAFIC (ex: Justification per
        # traffic line). Envoyes avec la cle "name".
        # Format config.json: {"traffic_fields": {"NPS - ... - Justification ...": "..."}}
        self.traffic_fields = config.get("traffic_fields") or {}
        self.session_id = None

        # Session persistante : le cookie jar gere automatiquement le scope
        # Path/Domain et capture les cookies rotes a chaque reponse (auth + appels).
        # Indispensable : certains endpoints (GET) rejettent un cookie rejoue
        # manuellement (BAD_COOKIE_HEADER) alors que le POST l'accepte.
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Active la log des requetes via env var ALGOSEC_DEBUG=1
        self.debug = os.environ.get("ALGOSEC_DEBUG", "").lower() in ("1", "true", "yes")

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def authenticate(self):
        """Authentification, capture du sessionId. Les cookies sont geres par la Session."""
        url = f"{self.base_url}/authentication/authenticate"
        payload = {
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        response = self.session.post(url, json=payload, headers=headers)
        if self.debug:
            print(f"[DEBUG] Set-Cookie (auth): {response.headers.get('Set-Cookie')}")
        response.raise_for_status()

        data = response.json()
        if data.get("status") != "Success":
            messages = data.get("messages", [])
            error_msg = messages[0]["message"] if messages else "Erreur inconnue"
            raise Exception(f"Echec authentification: {error_msg}")

        self.session_id = data["data"]["sessionId"]

        # Les cookies poses par le serveur sont deja dans self.session.cookies.
        # On recupere leurs Path pour l'auto-alignement du base_url.
        cookie_paths = {c.path for c in self.session.cookies if c.path}

        # Fallback : si le serveur n'a pose aucun cookie, on injecte le sessionId
        # sous les noms candidats dans le jar (scope sur le host du serveur).
        if not len(self.session.cookies):
            host = urlparse(self.server).hostname
            for name in self.COOKIE_CANDIDATES:
                self.session.cookies.set(name, self.session_id, domain=host)

        cookie_summary = ", ".join(f"{c.name}={(c.value or '')[:8]}..." for c in self.session.cookies)
        print(f"[OK] Authentification reussie. Session ID: {self.session_id[:8]}... | Cookies: {cookie_summary}")

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

    def _get_headers(self):
        """Headers communs : JSON. Les cookies sont ajoutes par la Session."""
        self._ensure_authenticated()
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
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

    def _log_debug(self, method, url, payload=None):
        if not self.debug:
            return
        cookies = "; ".join(f"{c.name}={(c.value or '')[:12]}..." for c in self.session.cookies)
        print(f"[DEBUG] {method} {url}")
        print(f"[DEBUG]   cookies envoyes: {cookies}")
        if payload is not None:
            print(f"[DEBUG]   body: {json.dumps(payload)[:300]}")

    def post(self, endpoint, payload):
        """Effectue un POST authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        self._log_debug("POST", url, payload)
        response = self.session.post(url, json=payload, headers=headers)
        self._raise_with_body(response, "POST", url)
        return response.json()

    def get(self, endpoint):
        """Effectue un GET authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        self._log_debug("GET", url)
        response = self.session.get(url, headers=headers)
        self._raise_with_body(response, "GET", url)
        return response.json()


if __name__ == "__main__":
    client = AlgosecClient()
    client.authenticate()

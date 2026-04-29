"""
Client AlgoSec FireFlow - Authentification et gestion de session.
"""

import json
import requests
import urllib3


class AlgosecClient:
    """Client pour interagir avec l'API REST FireFlow d'AlgoSec."""

    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            config = json.load(f)

        self.base_url = config["server"].rstrip("/") + "/FireFlow/api"
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", True)
        self.session_id = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def authenticate(self):
        """Authentification et recuperation du session ID."""
        url = f"{self.base_url}/authentication/authenticate"
        payload = {
            "username": self.username,
            "password": self.password
        }
        headers = {"Content-Type": "application/json"}

        response = requests.post(
            url, json=payload, headers=headers, verify=self.verify_ssl
        )
        response.raise_for_status()

        data = response.json()
        if data.get("status") == "Success":
            self.session_id = data["data"]["sessionId"]
            print(f"[OK] Authentification reussie. Session ID: {self.session_id[:8]}...")
            return self.session_id
        else:
            messages = data.get("messages", [])
            error_msg = messages[0]["message"] if messages else "Erreur inconnue"
            raise Exception(f"Echec authentification: {error_msg}")

    def _get_headers(self):
        """Retourne les headers avec le cookie de session."""
        if not self.session_id:
            raise Exception("Non authentifie. Appelez authenticate() d'abord.")
        return {
            "Content-Type": "application/json",
            "Cookie": f"FireFlow_Session={self.session_id}"
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

    def post(self, endpoint, payload):
        """Effectue un POST authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.post(
            url, json=payload, headers=self._get_headers(), verify=self.verify_ssl
        )
        self._raise_with_body(response, "POST", url)
        return response.json()

    def get(self, endpoint):
        """Effectue un GET authentifie."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.get(
            url, headers=self._get_headers(), verify=self.verify_ssl
        )
        self._raise_with_body(response, "GET", url)
        return response.json()


if __name__ == "__main__":
    client = AlgosecClient()
    client.authenticate()

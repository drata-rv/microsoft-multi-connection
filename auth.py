"""
auth.py
Handles token acquisition and caching for Microsoft Graph and Log Analytics APIs.
Uses client credentials grant (application permissions).
"""

import time
import requests
from dataclasses import dataclass, field


GRAPH_SCOPE = "https://graph.microsoft.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


@dataclass
class TokenCache:
    access_token: str = ""
    expires_at: float = 0.0
    scope: str = ""


class MSAuthClient:
    """
    Single app registration, dual-scope token management.
    Covers Graph API and Log Analytics (Sentinel KQL).
    """

    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    REFRESH_BUFFER_SECONDS = 300  # refresh 5 min before expiry

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._cache: dict[str, TokenCache] = {}

    def get_token(self, scope: str = GRAPH_SCOPE) -> str:
        cached = self._cache.get(scope)
        if cached and time.time() < cached.expires_at - self.REFRESH_BUFFER_SECONDS:
            return cached.access_token
        return self._fetch_token(scope)

    def _fetch_token(self, scope: str) -> str:
        url = self.TOKEN_URL.format(tenant_id=self.tenant_id)
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope,
        }
        resp = requests.post(url, data=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        self._cache[scope] = TokenCache(
            access_token=data["access_token"],
            expires_at=time.time() + data["expires_in"],
            scope=scope,
        )
        return data["access_token"]

    def graph_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.get_token(GRAPH_SCOPE)}",
            "Content-Type": "application/json",
        }

    def log_analytics_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.get_token(LOG_ANALYTICS_SCOPE)}",
            "Content-Type": "application/json",
        }

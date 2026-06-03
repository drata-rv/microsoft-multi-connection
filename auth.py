"""
auth.py
Token acquisition and caching for all Microsoft API surfaces.

Four distinct resource audiences are required:
    GRAPH_SCOPE           -- Microsoft Graph (Sentinel incidents/alerts, Purview,
                             Intune, Entra ID Protection)
    LOG_ANALYTICS_SCOPE   -- Log Analytics KQL queries (Sentinel workspace)
    ARM_SCOPE             -- Azure Resource Manager (Sentinel analytics rules)
    MDE_SCOPE             -- MDE REST API (api.securitycenter.microsoft.com)

The MDE REST API does NOT accept Graph-scoped tokens. Always use mde_headers()
for any request to api.securitycenter.microsoft.com.

All tokens are cached per-scope and refreshed 5 minutes before expiry.

Drata SA Team
"""

import time
import requests
from dataclasses import dataclass


GRAPH_SCOPE         = "https://graph.microsoft.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
ARM_SCOPE           = "https://management.azure.com/.default"
MDE_SCOPE           = "https://api.securitycenter.microsoft.com/.default"


@dataclass
class _TokenEntry:
    access_token: str
    expires_at: float


class MSAuthClient:
    """
    Single app registration, multi-scope token management.
    Covers Graph, Log Analytics, ARM, and MDE API surfaces.
    Thread-safety is not guaranteed; designed for single-threaded use.
    """

    _TOKEN_URL      = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _REFRESH_BUFFER = 300  # refresh 5 min before expiry

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        self._cache: dict[str, _TokenEntry] = {}

    # ------------------------------------------------------------------
    # Public header builders — one per API surface
    # ------------------------------------------------------------------

    def graph_headers(self) -> dict[str, str]:
        return self._bearer_headers(GRAPH_SCOPE)

    def log_analytics_headers(self) -> dict[str, str]:
        return self._bearer_headers(LOG_ANALYTICS_SCOPE)

    def arm_headers(self) -> dict[str, str]:
        """Headers for Azure Resource Manager (management.azure.com)."""
        return self._bearer_headers(ARM_SCOPE)

    def mde_headers(self) -> dict[str, str]:
        """
        Headers for the MDE REST API (api.securitycenter.microsoft.com).
        Graph-scoped tokens are rejected by this API — always use this method
        for any request to api.securitycenter.microsoft.com.
        """
        return self._bearer_headers(MDE_SCOPE)

    # ------------------------------------------------------------------
    # Internal token management
    # ------------------------------------------------------------------

    def _bearer_headers(self, scope: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token(scope)}",
            "Content-Type": "application/json",
        }

    def _get_token(self, scope: str) -> str:
        entry = self._cache.get(scope)
        if entry and time.time() < entry.expires_at - self._REFRESH_BUFFER:
            return entry.access_token
        return self._fetch_token(scope)

    def _fetch_token(self, scope: str) -> str:
        url = self._TOKEN_URL.format(tenant_id=self.tenant_id)
        resp = requests.post(
            url,
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         scope,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._cache[scope] = _TokenEntry(
            access_token=data["access_token"],
            expires_at=time.time() + data["expires_in"],
        )
        return data["access_token"]

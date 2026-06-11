"""
base.py
Base class for all Microsoft API connectors.

Provides:
    _get()      -- single-page GET with retry (429, 5xx) and configurable auth headers
    _post()     -- single-page POST with the same retry logic (used for KQL queries)
    _paginate() -- follows @odata.nextLink / nextLink automatically

Design decisions:
    - headers is a required parameter on _get, _post, and _paginate. Callers must
      pass the correct auth header set (graph_headers, mde_headers, arm_headers)
      explicitly. There is no default — omitting headers sends an unauthenticated
      request, which returns a clear 401 rather than silently using the wrong token.
    - Retry is a bounded loop, not recursion. A persistent 429 or 5xx cannot cause a
      stack overflow.
    - 5xx errors are retried with exponential backoff. 4xx errors (other than 429) are
      not retried — they indicate a client-side problem (auth, permissions, bad URL).

Drata SA Team
"""

import logging
import time
from typing import Dict, Generator, Optional

import requests
from auth import MSAuthClient

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

_MAX_RETRIES  = 5
_BACKOFF_BASE = 2  # seconds; doubles each retry for 5xx


class BaseConnector:
    """Subclass this for each Microsoft API surface."""

    def __init__(self, auth: MSAuthClient) -> None:
        self.auth    = auth
        self.session = requests.Session()

    def _get(
        self,
        url: str,
        params: Optional[Dict]           = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> dict:
        """
        Single-page GET with retry for 429 and 5xx responses.

        headers must be provided explicitly — pass self.auth.graph_headers(),
        self.auth.mde_headers(), self.auth.arm_headers(), etc. as appropriate.
        Omitting headers sends an unauthenticated request.
        """
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = self.session.get(url, headers=headers, params=params, timeout=30)

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                logger.warning(
                    "Rate limited by %s — waiting %ss (attempt %d/%d)",
                    url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            if resp.status_code in {500, 502, 503, 504}:
                wait = _BACKOFF_BASE ** attempt
                logger.warning(
                    "HTTP %d from %s — retrying in %ss (attempt %d/%d)",
                    resp.status_code, url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()

        # All retries exhausted — raise the last response as an error
        resp.raise_for_status()
        return {}  # unreachable; satisfies type checker

    def _post(
        self,
        url: str,
        headers: Dict[str, str],
        json: Optional[Dict] = None,
    ) -> dict:
        """
        Single-page POST with retry for 429 and 5xx responses.
        Mirrors _get retry logic. Used for API surfaces that require POST
        (e.g. Log Analytics KQL queries).
        """
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = self.session.post(url, headers=headers, json=json, timeout=60)

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                logger.warning(
                    "Rate limited by %s — waiting %ss (attempt %d/%d)",
                    url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            if resp.status_code in {500, 502, 503, 504}:
                wait = _BACKOFF_BASE ** attempt
                logger.warning(
                    "HTTP %d from %s — retrying in %ss (attempt %d/%d)",
                    resp.status_code, url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()

        resp.raise_for_status()
        return {}  # unreachable; satisfies type checker

    def _paginate(
        self,
        url: str,
        params: Optional[Dict]           = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Generator[dict, None, None]:
        """
        Follows @odata.nextLink (Graph) or nextLink (ARM/MDE) automatically.
        Yields individual items from the value array.

        params are sent only on the first request; nextLink encodes them already.
        Pass headers explicitly — same value you would pass to _get.
        """
        while url:
            data   = self._get(url, params=params, headers=headers)
            params = None  # only sent on first page; nextLink encodes them
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink") or data.get("nextLink")

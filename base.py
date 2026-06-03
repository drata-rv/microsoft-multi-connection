"""
base.py
Base class for all Microsoft product connectors.
Handles pagination, rate limiting, and common error handling.
"""

import logging
import time
from typing import Generator
import requests
from auth import MSAuthClient

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class BaseConnector:
    """
    Subclass this for each Microsoft product.
    Provides paginated Graph API calls and retry logic.
    """

    def __init__(self, auth: MSAuthClient):
        self.auth = auth
        self.session = requests.Session()

    def _get(self, url: str, params: dict = None, use_beta: bool = False) -> dict:
        headers = self.auth.graph_headers()
        resp = self.session.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 10))
            logger.warning("Rate limited. Waiting %s seconds.", retry_after)
            time.sleep(retry_after)
            return self._get(url, params, use_beta)

        resp.raise_for_status()
        return resp.json()

    def _paginate(self, url: str, params: dict = None) -> Generator[dict, None, None]:
        """
        Follows @odata.nextLink automatically.
        Yields individual items from the value array.
        """
        while url:
            data = self._get(url, params=params)
            params = None  # only send params on first call
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink")

"""
drata_client.py
Drata Custom Connections publisher.

Pushes collected Microsoft compliance data to a single Drata custom connection
via the Custom Connections v2 API using session-based full-replacement sync.

Session semantics:
    Each sync opens a session for the target resource, batches all current
    records into it, then completes the session. Completing a session makes all
    submitted records the active state and removes anything not part of this
    session. Each run is a full state replacement — Drata mirrors the latest
    Microsoft response exactly. No local state tracking is required.

Rate limits (Drata public API): 500 requests/min per source IP.
Records are batched at BATCH_SIZE per request to stay within this limit and
the 5 MB per-request body cap.

Drata SA Team
"""

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

_BASE_URL    = "https://public-api.drata.com/public/v2"
_BATCH_SIZE  = 100
_MAX_RETRIES = 5


class DrataPublisher:

    def __init__(self, api_key: str, connection_id: int) -> None:
        self._connection_id = connection_id
        self._http = requests.Session()
        self._http.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        })

    def sync_resource(
        self,
        resource_id: int,
        records: list[dict[str, Any]],
        resource_name: str = "",
    ) -> None:
        """
        Full-replacement sync for one Drata resource.

        Opens a session, pushes all records in batches, then completes the
        session. On any error, cancels the session so it does not remain
        IN_PROGRESS in Drata. An empty records list is treated as a no-op with
        a warning — preserving the last known state is safer than wiping it on
        a collection failure upstream.
        """
        label = resource_name or str(resource_id)

        if not records:
            logger.warning("sync_skipped resource=%s reason=no_records", label)
            return

        logger.info("sync_start resource=%s count=%d", label, len(records))
        session_id = self._create_session(resource_id)

        try:
            self._push_batches(resource_id, session_id, records, label)
            self._complete_session(resource_id, session_id)
            logger.info("sync_complete resource=%s", label)
        except Exception as exc:
            logger.error("sync_failed resource=%s error=%s — cancelling session", label, exc)
            self._cancel_session(resource_id, session_id)
            raise

    # -------------------------------------------------------------------------
    # Session lifecycle
    # -------------------------------------------------------------------------

    def _create_session(self, resource_id: int) -> str:
        url  = (
            f"{_BASE_URL}/custom-connections/{self._connection_id}"
            f"/resources/{resource_id}/sessions"
        )
        resp = self._request("POST", url)
        return resp["sessionId"]

    def _push_batches(
        self,
        resource_id: int,
        session_id: str,
        records: list[dict[str, Any]],
        label: str,
    ) -> None:
        url = (
            f"{_BASE_URL}/custom-connections/{self._connection_id}"
            f"/resources/{resource_id}/sessions/{session_id}"
        )
        for start in range(0, len(records), _BATCH_SIZE):
            batch = records[start : start + _BATCH_SIZE]
            self._request("POST", url, json={"data": batch})
            logger.debug(
                "batch_pushed resource=%s records=%d/%d",
                label, min(start + _BATCH_SIZE, len(records)), len(records),
            )

    def _complete_session(self, resource_id: int, session_id: str) -> None:
        self._session_action(resource_id, session_id, "complete")

    def _cancel_session(self, resource_id: int, session_id: str) -> None:
        """Best-effort cancel — never raises, safe to call from exception handlers."""
        try:
            self._session_action(resource_id, session_id, "cancel")
        except Exception as exc:
            logger.warning("session_cancel_failed session_id=%s error=%s", session_id, exc)

    def _session_action(self, resource_id: int, session_id: str, action: str) -> None:
        url = (
            f"{_BASE_URL}/custom-connections/{self._connection_id}"
            f"/resources/{resource_id}/sessions/{session_id}/actions"
        )
        self._request("POST", url, json={"action": action})

    # -------------------------------------------------------------------------
    # HTTP with bounded retry
    # -------------------------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = self._http.request(method, url, timeout=30, **kwargs)

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                logger.warning(
                    "drata_rate_limited url=%s wait=%ss attempt=%d/%d",
                    url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            if resp.status_code in {500, 502, 503, 504}:
                wait = 2 ** attempt
                logger.warning(
                    "drata_server_error status=%d url=%s wait=%ss attempt=%d/%d",
                    resp.status_code, url, wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json() if resp.content else {}

        # All retries exhausted
        resp.raise_for_status()
        return {}

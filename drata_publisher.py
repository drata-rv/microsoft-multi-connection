"""
drata_publisher.py
Pushes normalised compliance records to a Drata Custom Connection.

Uses the session-based upload flow from the Custom Data Records API:
    POST  /custom-connections/{connectionId}/resources/{resourceId}/sessions/{sessionId}
          -- upload records in inactive state (repeat for each batch)
    POST  /custom-connections/{connectionId}/resources/{resourceId}/sessions/{sessionId}/actions
          body: {"action": "complete"}
          -- activates all records; permanently deletes any prior records not in this session

This is a full replacement on every run. Records from previous runs that are not
re-submitted are removed when the session is completed.

Required environment variables:
    DRATA_API_KEY        -- API key from Drata Settings → API Keys (used as Bearer token)
    DRATA_CONNECTION_ID  -- Custom Connection ID (visible in Drata app URL or API)
    DRATA_RESOURCE_ID    -- Resource ID within the connection
                           Retrieve with:
                           GET /custom-connections/{connectionId}?expand[]=customResources

Drata SA Team
"""

import logging
import os
import uuid
from typing import List

import requests

logger = logging.getLogger(__name__)

_DRATA_BASE = "https://public-api.drata.com/public"
_BATCH_SIZE = 500


class DrataPublisher:
    def __init__(self) -> None:
        self._connection_id = os.environ["DRATA_CONNECTION_ID"]
        self._resource_id   = os.environ["DRATA_RESOURCE_ID"]
        self._http = requests.Session()
        self._http.headers.update({
            "Authorization": f"Bearer {os.environ['DRATA_API_KEY']}",
            "Content-Type":  "application/json",
        })

    def publish(self, records: List[dict]) -> None:
        """
        Upload all records under a single session then complete it.
        Completing the session permanently replaces all prior records for this resource.
        Skips publish if records list is empty.
        """
        if not records:
            logger.warning("publish_skipped — no records to upload")
            return

        session_id = str(uuid.uuid4())
        base = (
            f"{_DRATA_BASE}/custom-connections/{self._connection_id}"
            f"/resources/{self._resource_id}"
        )

        logger.info("drata_publish_start session=%s total_records=%d", session_id, len(records))

        batches = [records[i : i + _BATCH_SIZE] for i in range(0, len(records), _BATCH_SIZE)]
        for i, batch in enumerate(batches, 1):
            resp = self._http.post(
                f"{base}/sessions/{session_id}",
                json={"data": batch},
            )
            resp.raise_for_status()
            logger.info("drata_batch_ok batch=%d/%d records=%d", i, len(batches), len(batch))

        resp = self._http.post(
            f"{base}/sessions/{session_id}/actions",
            json={"action": "complete"},
        )
        resp.raise_for_status()
        logger.info("drata_publish_complete session=%s", session_id)

"""
drata_publisher.py
Pushes normalised compliance records to a Drata Custom Connection.

Uses the direct upsert endpoint from the Custom Data Records API:
    POST /custom-connections/{connectionId}/resources/{resourceId}/records
         body: {"data": [...]}
         -- records with matching IDs are updated; new records are created;
            records not included in the payload are left untouched.

This is an additive upsert, not a full replacement. Records for endpoints
that fail collection on a given run are preserved from the previous run
rather than deleted.

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
from typing import List

import requests

logger = logging.getLogger(__name__)

_DRATA_BASE = "https://public-api.drata.com/public"
_BATCH_SIZE = 500


class DrataPublisher:
    def __init__(self) -> None:
        self._url = (
            f"{_DRATA_BASE}/custom-connections/{os.environ['DRATA_CONNECTION_ID']}"
            f"/resources/{os.environ['DRATA_RESOURCE_ID']}/records"
        )
        self._http = requests.Session()
        self._http.headers.update({
            "Authorization": f"Bearer {os.environ['DRATA_API_KEY']}",
            "Content-Type":  "application/json",
        })

    def publish(self, records: List[dict]) -> None:
        """
        Upsert records in batches of 500. Skips if records list is empty.
        """
        if not records:
            logger.warning("publish_skipped — no records to upload")
            return

        batches = [records[i : i + _BATCH_SIZE] for i in range(0, len(records), _BATCH_SIZE)]
        logger.info("drata_publish_start total_records=%d batches=%d", len(records), len(batches))

        for i, batch in enumerate(batches, 1):
            resp = self._http.post(self._url, json={"data": batch})
            resp.raise_for_status()
            logger.info("drata_batch_ok batch=%d/%d records=%d", i, len(batches), len(batch))

        logger.info("drata_publish_complete total_records=%d", len(records))

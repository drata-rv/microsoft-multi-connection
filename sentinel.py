"""
sentinel.py
Microsoft Sentinel connector.
Covers: security incidents, alerts, analytics rules.
Sentinel data lives in Log Analytics; some metadata available via Graph Security API.

DCF targets: 27 instances (incidents, alert rules, threat detection posture)
"""

import logging
import requests
from auth import MSAuthClient, LOG_ANALYTICS_SCOPE
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

LOG_ANALYTICS_QUERY_URL = (
    "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
)

# Sentinel-specific Graph Security API endpoints
INCIDENTS_URL = f"{GRAPH_BASE}/security/incidents"
ALERTS_URL = f"{GRAPH_BASE}/security/alerts_v2"


class SentinelConnector(BaseConnector):
    """
    Dual-API connector: Graph Security API for incidents/alerts,
    Log Analytics for KQL-based rule and event queries.
    """

    def __init__(self, auth: MSAuthClient, workspace_id: str):
        super().__init__(auth)
        self.workspace_id = workspace_id
        self.query_url = LOG_ANALYTICS_QUERY_URL.format(workspace_id=workspace_id)

    # -------------------------------------------------------------------------
    # Graph Security API methods
    # -------------------------------------------------------------------------

    def get_incidents(self, top: int = 100) -> list[dict]:
        """
        Returns open and recently closed security incidents.
        Maps to DCFs covering incident response process evidence.
        """
        params = {
            "$top": top,
            "$orderby": "lastUpdateDateTime desc",
            "$filter": "status ne 'resolved'",
        }
        return list(self._paginate(INCIDENTS_URL, params=params))

    def get_alerts(self, top: int = 100) -> list[dict]:
        """
        Returns active security alerts.
        Maps to DCFs covering threat detection monitoring.
        """
        params = {
            "$top": top,
            "$orderby": "createdDateTime desc",
            "$filter": "status ne 'resolved'",
        }
        return list(self._paginate(ALERTS_URL, params=params))

    # -------------------------------------------------------------------------
    # Log Analytics KQL methods
    # -------------------------------------------------------------------------

    def _kql_query(self, query: str, timespan: str = "P7D") -> list[dict]:
        """
        Executes a KQL query against the Log Analytics workspace.
        timespan uses ISO 8601 duration format (P7D = last 7 days).
        """
        headers = self.auth.log_analytics_headers()
        payload = {"query": query, "timespan": timespan}
        resp = self.session.post(
            self.query_url, headers=headers, json=payload, timeout=60
        )
        resp.raise_for_status()
        data = resp.json()

        # Log Analytics returns columnar data; convert to list of dicts
        tables = data.get("tables", [])
        if not tables:
            return []

        table = tables[0]
        columns = [col["name"] for col in table["columns"]]
        return [dict(zip(columns, row)) for row in table["rows"]]

    def get_analytics_rules(self) -> list[dict]:
        """
        Returns all enabled analytics (detection) rules.
        Maps to DCFs covering detection rule configuration evidence.
        """
        query = """
        _SentinelHealth
        | where SentinelResourceKind == "ScheduledAnalyticsRule"
        | where Status == "Success"
        | summarize arg_max(TimeGenerated, *) by SentinelResourceName
        | project RuleName=SentinelResourceName, LastRun=TimeGenerated, Status
        """
        return self._kql_query(query)

    def get_threat_detections_summary(self, timespan: str = "P30D") -> list[dict]:
        """
        Returns aggregated threat detections by category.
        Maps to DCFs requiring evidence of continuous threat monitoring.
        """
        query = """
        SecurityAlert
        | summarize Count=count(), LastSeen=max(TimeGenerated)
            by AlertName, AlertSeverity, ProviderName
        | order by Count desc
        """
        return self._kql_query(query, timespan=timespan)

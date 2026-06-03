"""
sentinel.py
Microsoft Sentinel connector.

Three distinct API surfaces:
    1. Graph Security API     -- incidents and alerts
    2. Log Analytics API      -- KQL queries (threat detection summary)
    3. Azure Resource Manager -- analytics rules inventory

Analytics rules are a control-plane resource, not a log entry. They must be
fetched from ARM. The _SentinelHealth table is NOT used here — it requires
opt-in workspace configuration and only reflects health events, not the full
rule inventory.

Required caller parameters (all four needed when sentinel is in --products):
    workspace_id     -- Log Analytics Workspace ID (GUID) for KQL queries
    subscription_id  -- Azure subscription ID for ARM rules fetch
    resource_group   -- resource group containing the Sentinel workspace
    workspace_name   -- ARM resource name of the Log Analytics workspace

DCF targets: incidents, alert rules, threat detection posture

Drata SA Team
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

LOG_ANALYTICS_QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
_SENTINEL_API_VERSION   = "2023-02-01"

INCIDENTS_URL = f"{GRAPH_BASE}/security/incidents"
ALERTS_V2_URL = f"{GRAPH_BASE}/security/alerts_v2"


class SentinelConnector(BaseConnector):
    """
    Sentinel data via Graph Security API, Log Analytics KQL, and ARM.
    Each API surface uses a different token scope; auth.py provides a
    dedicated header method for each.
    """

    def __init__(
        self,
        auth: MSAuthClient,
        workspace_id: str,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
    ) -> None:
        super().__init__(auth)
        self.workspace_id    = workspace_id
        self.subscription_id = subscription_id
        self.resource_group  = resource_group
        self.workspace_name  = workspace_name
        self._query_url = LOG_ANALYTICS_QUERY_URL.format(workspace_id=workspace_id)
        self._arm_rules_url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"/providers/Microsoft.SecurityInsights/alertRules"
            f"?api-version={_SENTINEL_API_VERSION}"
        )

    # -------------------------------------------------------------------------
    # Graph Security API — incidents and alerts
    # -------------------------------------------------------------------------

    def get_incidents(self, top: int = 100) -> list:
        """
        Returns open and in-progress security incidents.
        Filtered client-side — $filter on status is not reliably supported
        on this endpoint and may silently return wrong results.
        Maps to DCFs covering incident response process evidence.
        """
        params = {"$top": top}
        raw = list(self._paginate(INCIDENTS_URL, params=params))
        return [i for i in raw if i.get("status") != "resolved"]

    def get_alerts(self, top: int = 100) -> list:
        """
        Returns active security alerts.
        Filtered client-side — alerts_v2 OData filter support is minimal and
        not fully documented; $filter may be silently ignored or return 400.
        Maps to DCFs covering threat detection monitoring.
        """
        params = {"$top": top}
        raw = list(self._paginate(ALERTS_V2_URL, params=params))
        return [a for a in raw if a.get("status") != "resolved"]

    # -------------------------------------------------------------------------
    # Azure Resource Manager — analytics rules (authoritative inventory)
    # -------------------------------------------------------------------------

    def get_analytics_rules(self) -> list:
        """
        Returns all Sentinel analytics rules from the ARM API.

        ARM is the authoritative source for rule inventory. The Log Analytics
        _SentinelHealth table is NOT used because it requires opt-in workspace
        configuration, only reflects health events (not all rules), and
        silently returns empty results if the feature is not enabled.

        Maps to DCFs covering detection rule configuration evidence.
        """
        return list(
            self._paginate(self._arm_rules_url, headers=self.auth.arm_headers())
        )

    # -------------------------------------------------------------------------
    # Log Analytics KQL — threat detection summary
    # -------------------------------------------------------------------------

    def get_threat_detections_summary(self, timespan: str = "P30D") -> list:
        """
        Aggregated threat detections by category from Log Analytics.
        timespan uses ISO 8601 duration format (P30D = last 30 days).
        Maps to DCFs requiring evidence of continuous threat monitoring.
        """
        query = """
        SecurityAlert
        | summarize Count=count(), LastSeen=max(TimeGenerated)
            by AlertName, AlertSeverity, ProviderName
        | order by Count desc
        """
        return self._kql_query(query, timespan=timespan)

    def _kql_query(self, query: str, timespan: str = "P7D") -> list:
        """KQL query against the Log Analytics workspace (Log Analytics token scope)."""
        resp = self.session.post(
            self._query_url,
            headers=self.auth.log_analytics_headers(),
            json={"query": query, "timespan": timespan},
            timeout=60,
        )
        resp.raise_for_status()
        tables = resp.json().get("tables", [])
        if not tables:
            return []
        table   = tables[0]
        columns = [col["name"] for col in table["columns"]]
        return [dict(zip(columns, row)) for row in table["rows"]]

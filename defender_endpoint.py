"""
defender_endpoint.py
Microsoft Defender for Endpoint connector.

Uses the MDE REST API (api.securitycenter.microsoft.com) exclusively.
The Graph Security API is NOT used here — it provides less telemetry for
endpoint-specific data, and its listMachines action is not an addressable
resource URL.

AUTH: All MDE REST API calls require a token with audience
    https://api.securitycenter.microsoft.com
    NOT the Graph audience. Graph-scoped tokens are rejected with 401.
    Use self.auth.mde_headers() for every request to api.securitycenter.microsoft.com.

get_exploit_guard_policy_coverage is an exception: exploit guard settings live in
Intune device configuration profiles (Graph), not the MDE REST API. It uses the
default graph_headers() via BaseConnector.

Required permissions (Application type, admin consent required):
    Machine.Read.All                       -- device inventory, protection status
    Alert.Read.All                         -- threat detections
    DeviceManagementConfiguration.Read.All -- exploit guard policy profiles (Graph/Intune)

DCF targets: endpoint inventory, protection status, threat alerts,
             vulnerability exposure, exploit guard policy coverage

Drata SA Team
"""

import logging
from typing import Optional
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

MDE_BASE                = "https://api.securitycenter.microsoft.com/api"
MDE_MACHINES_URL        = f"{MDE_BASE}/machines"
MDE_ALERTS_URL          = f"{MDE_BASE}/alerts"
MDE_VULNERABILITIES_URL = f"{MDE_BASE}/vulnerabilities"
MDE_EXPOSURE_URL        = f"{MDE_BASE}/exposureScore"


class DefenderEndpointConnector(BaseConnector):
    """
    Defender for Endpoint connector via the MDE REST API.
    All MDE REST API methods pass mde_headers() explicitly — never fall through
    to the Graph default in BaseConnector._get.
    """

    def __init__(self, auth: MSAuthClient) -> None:
        super().__init__(auth)

    def get_machines(self, filter_expr: Optional[str] = None) -> list:
        """
        Returns all MDE-onboarded devices with health and risk state.
        Requires: Machine.Read.All
        Maps to DCFs requiring endpoint inventory and protection status evidence.
        """
        params = {}
        if filter_expr:
            params["$filter"] = filter_expr
        return list(
            self._paginate(MDE_MACHINES_URL, params=params or None, headers=self.auth.mde_headers())
        )

    def get_alerts(self, severity: Optional[str] = None, top: int = 100) -> list:
        """
        Returns MDE threat alerts, optionally filtered by severity.
        Severity values: Informational, Low, Medium, High
        Requires: Alert.Read.All
        Maps to DCFs covering active threat detection evidence.
        """
        params: dict = {"$top": top, "$orderby": "alertCreationTime desc"}
        if severity:
            params["$filter"] = f"severity eq '{severity}'"
        return list(
            self._paginate(MDE_ALERTS_URL, params=params, headers=self.auth.mde_headers())
        )

    def get_exposure_score(self) -> dict:
        """
        Returns the organisation-level exposure score.
        Requires: Machine.Read.All
        Maps to DCFs requiring evidence of vulnerability exposure posture.
        """
        return self._get(MDE_EXPOSURE_URL, headers=self.auth.mde_headers())

    def get_software_vulnerabilities(self, top: int = 200) -> list:
        """
        Returns CVEs with device exposure counts, ordered by blast radius.
        Requires: Machine.Read.All
        Supplements (does not replace) the native Defender VMS Drata integration.
        Maps to DCFs covering vulnerability remediation tracking beyond patch status.
        """
        params = {"$top": top, "$orderby": "exposedMachines desc"}
        return list(
            self._paginate(MDE_VULNERABILITIES_URL, params=params, headers=self.auth.mde_headers())
        )

    def get_exploit_guard_policy_coverage(self) -> list:
        """
        Returns Windows endpoint protection configuration profiles with aggregate
        device deployment status.

        Each profile object includes deviceStatusSummary showing how many devices
        have the policy in succeeded, failed, error, or conflict state. This is
        policy coverage evidence — it shows that exploit guard policies are defined
        and what fraction of devices have them applied.

        Note: this is NOT per-device exploit protection settings. Retrieving that
        requires a separate query per profile against deviceStatuses.

        Requires: DeviceManagementConfiguration.Read.All (Graph/Intune endpoint)
        Maps to exploit guard and process protection DCFs.
        """
        url = f"{GRAPH_BASE}/deviceManagement/deviceConfigurations"
        params = {
            "$filter": "isof('microsoft.graph.windows10EndpointProtectionConfiguration')",
            "$expand": "deviceStatusSummary",
        }
        return list(self._paginate(url, params=params, headers=self.auth.graph_headers()))

"""
defender_identity.py
Entra ID Protection connector.

PRODUCT NOTE:
    Despite the module name (kept for import compatibility with main.py), this
    connector targets Entra ID Protection (formerly Azure AD Identity Protection),
    NOT Microsoft Defender for Identity. These are two distinct products:

      Entra ID Protection  — cloud identity risk signals: risky sign-ins, risky
                             users, risk detections. Covered here.
      Defender for Identity — on-premises Active Directory threats: lateral
                             movement, pass-the-hash, reconnaissance. Separate
                             API surface; not implemented. Raise as a separate
                             workstream if on-premises AD coverage is required.

Covers (cloud identity risk via Entra ID Protection):
    - Risky users
    - Risk detections (events that contributed to a user or sign-in risk score)
    - Risky service principals
    - Conditional Access named locations (network trust boundaries)

Required permissions (Application type, admin consent required):
    IdentityRiskyUser.Read.All              -- risky users
    IdentityRiskEvent.Read.All              -- risk detections
    IdentityRiskyServicePrincipal.Read.All  -- risky service principals
    Policy.Read.All                         -- Conditional Access named locations

DCF targets: identity risk posture, risky user monitoring, CA policy coverage

Drata SA Team
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

RISKY_USERS_URL              = f"{GRAPH_BASE}/identityProtection/riskyUsers"
RISK_DETECTIONS_URL          = f"{GRAPH_BASE}/identityProtection/riskDetections"
RISKY_SERVICE_PRINCIPALS_URL = f"{GRAPH_BASE}/identityProtection/riskyServicePrincipals"
NAMED_LOCATIONS_URL          = f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations"


class DefenderIdentityConnector(BaseConnector):
    """
    Entra ID Protection connector.
    Class name retained as DefenderIdentityConnector for import compatibility.
    """

    def __init__(self, auth: MSAuthClient) -> None:
        super().__init__(auth)

    def get_risky_users(self, top: int = 200) -> list:
        """
        Returns users with an active risk state (atRisk or confirmedCompromised).
        Filtered client-side — combining riskState values via $filter requires 'or',
        which Graph handles inconsistently on this endpoint.
        Requires: IdentityRiskyUser.Read.All
        Maps to DCFs covering risky user identification and response evidence.
        """
        params = {"$top": top}
        raw = list(self._paginate(RISKY_USERS_URL, params=params, headers=self.auth.graph_headers()))
        return [u for u in raw if u.get("riskState") in {"atRisk", "confirmedCompromised"}]

    def get_risk_detections(self, top: int = 200) -> list:
        """
        Returns individual risk detection events contributing to user risk scores.
        Requires: IdentityRiskEvent.Read.All
        Maps to DCFs requiring evidence of identity risk event monitoring.
        """
        params = {
            "$top":     top,
            "$orderby": "detectedDateTime desc",
        }
        return list(self._paginate(RISK_DETECTIONS_URL, params=params, headers=self.auth.graph_headers()))

    def get_risky_service_principals(self, top: int = 200) -> list:
        """
        Returns service principals with an active risk state.
        Requires: IdentityRiskyServicePrincipal.Read.All — a separate permission
        from IdentityRiskyUser.Read.All; must be explicitly granted in the App
        Registration.
        Maps to DCFs covering non-human identity risk monitoring.
        """
        params = {"$top": top}
        raw = list(self._paginate(RISKY_SERVICE_PRINCIPALS_URL, params=params, headers=self.auth.graph_headers()))
        return [sp for sp in raw if sp.get("riskState") in {"atRisk", "confirmedCompromised"}]

    def get_conditional_access_named_locations(self) -> list:
        """
        Returns Conditional Access named locations (IP ranges and country sets).
        These define the network trust boundaries used in CA policies.
        Requires: Policy.Read.All
        Maps to DCFs covering network access control and CA policy evidence.
        """
        return list(self._paginate(NAMED_LOCATIONS_URL, headers=self.auth.graph_headers()))

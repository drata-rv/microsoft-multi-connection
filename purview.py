"""
purview.py
Microsoft Purview connector.

DLP SCOPE NOTE:
    Purview DLP policies and DLP violation events are NOT accessible through
    the Microsoft Graph API. The endpoint /security/dataLossPreventionPolicies
    does not exist (v1.0 or beta), and the permission
    DataLossPreventionPolicy.Read.All does not exist in Microsoft Graph.

    DLP data requires the Office 365 Management Activity API
    (manage.office.com/api/v1.0/{tenant}/activity/feed/...) with a separate
    auth flow and subscription setup. That is a distinct integration workstream.
    If DLP evidence is required by the DCFs in scope, raise it as a separate
    engagement item.

What this connector provides (achievable via Graph today):
    - Sensitivity labels defined in the tenant
    - Sensitive information types (built-in and custom)

Required permissions:
    InformationProtectionPolicy.Read.All  -- sensitivity labels
    DataClassification.Read.All           -- sensitive information types

DCF targets: data classification schema, sensitivity label coverage

Drata SA Team
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE, GRAPH_BETA

logger = logging.getLogger(__name__)

SENSITIVITY_LABELS_URL   = f"{GRAPH_BASE}/security/informationProtection/sensitivityLabels"
SENSITIVE_INFO_TYPES_URL = f"{GRAPH_BETA}/dataClassification/sensitiveTypes"


class PurviewConnector(BaseConnector):
    """
    Purview data classification and sensitivity label connector.
    Several endpoints remain in beta as of early 2026 — validate endpoint
    availability against the tenant's license tier (E3 vs E5).
    """

    def __init__(self, auth: MSAuthClient) -> None:
        super().__init__(auth)

    def get_sensitivity_labels(self) -> list:
        """
        Returns all sensitivity labels defined in the tenant.
        Requires: InformationProtectionPolicy.Read.All
        Maps to DCFs covering data classification schema evidence.
        """
        return list(self._paginate(SENSITIVITY_LABELS_URL))

    def get_sensitive_info_types(self) -> list:
        """
        Returns all sensitive information types (built-in and custom).
        Requires: DataClassification.Read.All
        Note: beta endpoint — if it returns 404, confirm the tenant's Purview
        license tier supports the dataClassification APIs.
        Maps to DCFs requiring evidence of data classification definitions.
        """
        return list(self._paginate(SENSITIVE_INFO_TYPES_URL))

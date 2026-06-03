"""
purview.py
Microsoft Purview connector.
Covers: DLP policies, DLP incidents, sensitivity labels, data classification.

DCF targets: 10 instances (DLP policy coverage, data classification posture)
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE, GRAPH_BETA

logger = logging.getLogger(__name__)

# Purview endpoints mix v1.0 and beta; beta has broader DLP coverage
DLP_POLICIES_URL = f"{GRAPH_BETA}/security/dataLossPreventionPolicies"
DLP_EVENTS_URL = f"{GRAPH_BETA}/security/alerts"
SENSITIVITY_LABELS_URL = f"{GRAPH_BASE}/security/informationProtection/sensitivityLabels"
DATA_CLASSIFICATIONS_URL = f"{GRAPH_BETA}/dataClassification/sensitiveTypes"


class PurviewConnector(BaseConnector):
    """
    Purview compliance and DLP connector.
    Note: Several Purview APIs are still in beta as of early 2026.
    Validate endpoint availability against tenant's license tier.
    """

    def __init__(self, auth: MSAuthClient):
        super().__init__(auth)

    def get_dlp_policies(self) -> list[dict]:
        """
        Returns all DLP policies and their enabled/disabled state.
        Maps to DCFs requiring evidence that DLP controls are configured.
        """
        return list(self._paginate(DLP_POLICIES_URL))

    def get_sensitivity_labels(self) -> list[dict]:
        """
        Returns all sensitivity labels defined in the tenant.
        Maps to DCFs covering data classification schema evidence.
        """
        return list(self._paginate(SENSITIVITY_LABELS_URL))

    def get_sensitive_info_types(self) -> list[dict]:
        """
        Returns all sensitive information types (built-in and custom).
        Maps to DCFs requiring evidence of data classification definitions.
        """
        return list(self._paginate(DATA_CLASSIFICATIONS_URL))

    def get_dlp_incidents(self, top: int = 100) -> list[dict]:
        """
        Returns recent DLP policy match incidents.
        Filters to DLP category alerts only.
        Maps to DCFs requiring evidence of DLP monitoring activity.
        """
        params = {
            "$top": top,
            "$filter": "category eq 'dataLossPrevention'",
            "$orderby": "createdDateTime desc",
        }
        return list(self._paginate(DLP_EVENTS_URL, params=params))

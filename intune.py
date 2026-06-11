"""
intune.py
Microsoft Intune enhancement connector.

The native Drata M365 integration covers basic device compliance and identity sync.
This connector targets the advanced device management DCFs the native integration
does not reach: configuration profiles, Update Rings, and noncompliant device tracking.

Required permissions:
    DeviceManagementManagedDevices.Read.All   -- device inventory, compliance state
    DeviceManagementConfiguration.Read.All    -- configuration profiles, Update Rings

DCF targets: device config profiles, Update Rings, compliance policies,
             noncompliant device tracking

Drata SA Team
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

DEVICE_CONFIGS_URL      = f"{GRAPH_BASE}/deviceManagement/deviceConfigurations"
COMPLIANCE_POLICIES_URL = f"{GRAPH_BASE}/deviceManagement/deviceCompliancePolicies"
# Dedicated endpoint for Update Rings — querying deviceConfigurations with isof()
# returns the base type and silently omits Update Ring-specific fields such as
# qualityUpdatesDeferralPeriodInDays and featureUpdatesDeferralPeriodInDays.
UPDATE_RINGS_URL        = f"{GRAPH_BASE}/deviceManagement/windowsUpdateForBusinessConfigurations"
MANAGED_DEVICES_URL     = f"{GRAPH_BASE}/deviceManagement/managedDevices"


class IntuneConnector(BaseConnector):
    """
    Intune advanced device management connector targeting configuration and policy
    compliance evidence beyond what the native Drata M365 integration provides.
    """

    def __init__(self, auth: MSAuthClient) -> None:
        super().__init__(auth)

    def get_device_configurations(self) -> list:
        """
        Returns all device configuration profiles (security baselines, BitLocker,
        Firewall, endpoint protection, etc.) with per-policy deployment status.
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs requiring evidence that endpoint configuration policies are
        defined and deployed.
        """
        params = {
            "$expand": "deviceStatusSummary",
        }
        return list(self._paginate(DEVICE_CONFIGS_URL, params=params, headers=self.auth.graph_headers()))

    def get_windows_update_rings(self) -> list:
        """
        Returns Windows Update for Business ring configurations.
        Uses the dedicated windowsUpdateForBusinessConfigurations endpoint — NOT
        deviceConfigurations. Querying deviceConfigurations with isof() filtering
        returns the base type and omits Update Ring-specific fields (deferral
        periods, businessReadyUpdatesOnly, etc.).
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs covering patch management policy evidence.
        """
        return list(self._paginate(UPDATE_RINGS_URL, headers=self.auth.graph_headers()))

    def get_compliance_policies(self) -> list:
        """
        Returns all device compliance policies.
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs requiring evidence that compliance policy baselines exist.
        """
        return list(self._paginate(COMPLIANCE_POLICIES_URL, headers=self.auth.graph_headers()))

    def get_noncompliant_devices(self) -> list:
        """
        Returns devices currently in a noncompliant state.
        Requires: DeviceManagementManagedDevices.Read.All
        Maps to DCFs requiring evidence of compliance gap monitoring.
        """
        params = {
            "$filter": "complianceState eq 'noncompliant'",
            "$select": (
                "id,deviceName,operatingSystem,complianceState,"
                "lastSyncDateTime,userDisplayName"
            ),
            "$orderby": "lastSyncDateTime desc",
        }
        return list(self._paginate(MANAGED_DEVICES_URL, params=params, headers=self.auth.graph_headers()))

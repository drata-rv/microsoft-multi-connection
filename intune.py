"""
intune.py
Microsoft Intune enhancement connector.

The native Drata M365 integration covers basic device compliance and identity sync.
This connector targets the advanced device management DCFs the native integration
does not reach: configuration profiles, Update Rings, app protection policies,
enrollment configurations, and noncompliant device tracking.

Required permissions:
    DeviceManagementManagedDevices.Read.All   -- device inventory, compliance state
    DeviceManagementConfiguration.Read.All    -- configuration profiles, Update Rings,
                                                 enrollment configs, app protection policies

DCF targets: device config profiles, Update Rings, app protection policies,
             mobile device configs, noncompliant device tracking

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
APP_PROTECTION_URL      = f"{GRAPH_BASE}/deviceAppManagement/managedAppPolicies"
MANAGED_DEVICES_URL     = f"{GRAPH_BASE}/deviceManagement/managedDevices"
ENROLLMENT_CONFIGS_URL  = f"{GRAPH_BASE}/deviceManagement/deviceEnrollmentConfigurations"


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
        return list(self._paginate(DEVICE_CONFIGS_URL, params=params))

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
        params = {}
        return list(self._paginate(UPDATE_RINGS_URL, params=params))

    def get_compliance_policies(self) -> list:
        """
        Returns all device compliance policies.
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs requiring evidence that compliance policy baselines exist.
        """
        return list(self._paginate(COMPLIANCE_POLICIES_URL))

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
        return list(self._paginate(MANAGED_DEVICES_URL, params=params))

    def get_app_protection_policies(self) -> list:
        """
        Returns MAM app protection policies (iOS and Android).
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs covering mobile device data protection evidence.
        """
        return list(self._paginate(APP_PROTECTION_URL))

    def get_enrollment_configurations(self) -> list:
        """
        Returns device enrollment profiles and restrictions.
        Requires: DeviceManagementConfiguration.Read.All
        Maps to DCFs covering device onboarding control evidence.
        """
        return list(self._paginate(ENROLLMENT_CONFIGS_URL))

"""
intune.py
Microsoft Intune enhancement connector.
Native Drata M365 integration covers basic device compliance and identity sync.
This connector targets the advanced device management DCFs that the native
integration does not reach.

DCF targets: ~10 instances (device config profiles, update rings,
             app protection policies, mobile device configs)
"""

import logging
from auth import MSAuthClient
from base import BaseConnector, GRAPH_BASE

logger = logging.getLogger(__name__)

DEVICE_CONFIGS_URL = f"{GRAPH_BASE}/deviceManagement/deviceConfigurations"
COMPLIANCE_POLICIES_URL = f"{GRAPH_BASE}/deviceManagement/deviceCompliancePolicies"
UPDATE_RINGS_URL = f"{GRAPH_BASE}/deviceManagement/deviceConfigurations"
APP_PROTECTION_POLICIES_URL = f"{GRAPH_BASE}/deviceAppManagement/managedAppPolicies"
MANAGED_DEVICES_URL = f"{GRAPH_BASE}/deviceManagement/managedDevices"
NONCOMPLIANT_DEVICES_URL = f"{GRAPH_BASE}/deviceManagement/managedDevices"
ENROLLMENT_PROFILES_URL = f"{GRAPH_BASE}/deviceManagement/deviceEnrollmentConfigurations"


class IntuneConnector(BaseConnector):
    """
    Intune custom connection targeting device configuration and policy
    compliance evidence beyond what the native Drata M365 integration provides.

    Requires:
        DeviceManagementManagedDevices.Read.All
        DeviceManagementConfiguration.Read.All
    """

    def __init__(self, auth: MSAuthClient):
        super().__init__(auth)

    def get_device_configurations(self) -> list[dict]:
        """
        Returns all device configuration profiles (security baselines,
        BitLocker, Firewall, etc.).
        Maps to DCFs requiring evidence that endpoint configuration
        policies are defined and deployed.
        """
        params = {
            "$select": "id,displayName,description,lastModifiedDateTime,deviceStatusSummary",
        }
        return list(self._paginate(DEVICE_CONFIGS_URL, params=params))

    def get_windows_update_rings(self) -> list[dict]:
        """
        Returns Windows Update for Business ring configurations.
        Filters to WindowsUpdateForBusinessConfiguration OData type.
        Maps to DCFs covering patch management policy evidence.
        """
        params = {
            "$filter": "isof('microsoft.graph.windowsUpdateForBusinessConfiguration')",
            "$select": "id,displayName,qualityUpdatesDeferralPeriodInDays,"
                       "featureUpdatesDeferralPeriodInDays,businessReadyUpdatesOnly",
        }
        return list(self._paginate(UPDATE_RINGS_URL, params=params))

    def get_compliance_policies(self) -> list[dict]:
        """
        Returns all device compliance policies.
        Maps to DCFs requiring evidence that compliance policy baselines exist.
        """
        return list(self._paginate(COMPLIANCE_POLICIES_URL))

    def get_noncompliant_devices(self) -> list[dict]:
        """
        Returns devices currently in a noncompliant state.
        Maps to DCFs requiring evidence of compliance gap monitoring.
        """
        params = {
            "$filter": "complianceState eq 'noncompliant'",
            "$select": "id,deviceName,operatingSystem,complianceState,"
                       "lastSyncDateTime,userDisplayName",
            "$orderby": "lastSyncDateTime desc",
        }
        return list(self._paginate(NONCOMPLIANT_DEVICES_URL, params=params))

    def get_app_protection_policies(self) -> list[dict]:
        """
        Returns MAM app protection policies (iOS and Android).
        Maps to DCFs covering mobile device data protection evidence.
        """
        return list(self._paginate(APP_PROTECTION_POLICIES_URL))

    def get_enrollment_configurations(self) -> list[dict]:
        """
        Returns device enrollment profiles and restrictions.
        Maps to DCFs covering device onboarding control evidence.
        """
        return list(self._paginate(ENROLLMENT_PROFILES_URL))

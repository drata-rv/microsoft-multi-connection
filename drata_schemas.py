from __future__ import annotations

"""
drata_schemas.py
Normalizers that map raw Microsoft API records to the Drata evidence schema.

Every normalizer receives a raw Microsoft API record and returns a dict
conforming to this schema — no more, no less:

    {
      "id":            string  -- Microsoft entity ID (stable across syncs)
      "service":       string  -- sentinel | purview | mde | entra_id | intune
      "evidenceType":  string  -- analytics_rule | incident | risky_user | ...
      "name":          string  -- human-readable label shown in the Drata UI
      "status":        string  -- see STATUS VOCABULARY below
      "severity":      string  -- High | Medium | Low | Critical | Informational
      "owner":         string  -- assignee, userPrincipalName, publisherName, etc.
      "affectedCount": number  -- exposedMachines, failedDeviceCount, detection count
      "score":         number  -- cvssV3, qualityDeferralDays, sensitivity order
      "timestamp":     string  -- ISO 8601, most recent meaningful date for the record
    }

STATUS VOCABULARY
    ACTIVE        -- open incident or alert
    ENABLED       -- rule or policy is switched on
    DISABLED      -- rule or policy is switched off       → test should flag
    CONFIGURED    -- policy, ring, or label exists
    COMPLIANT     -- device or principal meets requirements
    NONCOMPLIANT  -- confirmed gap                        → test should fail
    AT_RISK       -- user or principal has elevated identity risk
    REMEDIATED    -- risk has been addressed
    RESOLVED      -- incident or alert is closed
    NO_RESPONSE   -- Microsoft returned nothing           → test should fail
    INVALID       -- data failed validation               → test should fail

Fields with a None value are omitted so Drata receives a clean sparse record
rather than one full of null values.

Drata SA Team
"""

from typing import Any


def _build(**kwargs: Any) -> dict[str, Any]:
    """Construct a schema record, dropping any key whose value is None."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _risk_state(raw: str | None) -> str:
    """
    Normalise Entra ID Protection riskState strings to the status vocabulary.
    Defaults to AT_RISK for any unrecognised value — conservative by design.
    """
    if raw in {"atRisk", "confirmedCompromised"}:
        return "AT_RISK"
    if raw in {"remediated", "dismissedAsFixed"}:
        return "REMEDIATED"
    return "AT_RISK"


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

def normalize_analytics_rule(r: dict) -> dict:
    """
    Source: ARM GET .../providers/Microsoft.SecurityInsights/alertRules
    ARM nests config under 'properties'; the resource name is the stable ID.
    Test signal: status == DISABLED means a detection rule is off.
    """
    props = r.get("properties", {})
    return _build(
        id=r.get("name"),
        service="sentinel",
        evidenceType="analytics_rule",
        name=props.get("displayName"),
        status="ENABLED" if props.get("enabled") else "DISABLED",
        severity=props.get("severity"),
        timestamp=props.get("lastModifiedUtc"),
    )


def normalize_incident(r: dict) -> dict:
    """
    Source: Graph GET /security/incidents
    Test signal: status == ACTIVE means open incidents require attention.
    """
    raw = r.get("status", "")
    return _build(
        id=r.get("id"),
        service="sentinel",
        evidenceType="incident",
        name=r.get("title"),
        status="ACTIVE" if raw in {"active", "inProgress"} else "RESOLVED",
        severity=r.get("severity"),
        owner=r.get("assignedTo"),
        timestamp=r.get("lastUpdateDateTime"),
    )


def normalize_alert(r: dict) -> dict:
    """
    Source: Graph GET /security/alerts_v2
    Test signal: status == ACTIVE means unresolved alerts need review.
    """
    return _build(
        id=r.get("id"),
        service="sentinel",
        evidenceType="alert",
        name=r.get("title"),
        status="RESOLVED" if r.get("status") == "resolved" else "ACTIVE",
        severity=r.get("severity"),
        owner=r.get("assignedTo"),
        timestamp=r.get("lastUpdateDateTime") or r.get("createdDateTime"),
    )


def normalize_threat_detection(r: dict) -> dict:
    """
    Source: Log Analytics KQL against SecurityAlert table (aggregated)
    No stable Microsoft ID exists for KQL aggregation rows; AlertName is used
    as a surrogate so repeated syncs upsert rather than create duplicates.
    Test signal: affectedCount > 0 confirms active threat detection activity.
    """
    alert_name = r.get("AlertName")
    return _build(
        id=alert_name,
        service="sentinel",
        evidenceType="threat_detection",
        name=alert_name,
        status="ACTIVE",
        severity=r.get("AlertSeverity"),
        owner=r.get("ProviderName"),
        affectedCount=r.get("Count"),
        timestamp=str(r["LastSeen"]) if r.get("LastSeen") else None,
    )


# ── Microsoft Purview ─────────────────────────────────────────────────────────

def normalize_sensitivity_label(r: dict) -> dict:
    """
    Source: Graph GET /security/informationProtection/sensitivityLabels
    score holds the numeric sensitivity order (lower = less sensitive).
    Test signal: NO_RESPONSE means no labels are defined.
    """
    return _build(
        id=r.get("id"),
        service="purview",
        evidenceType="sensitivity_label",
        name=r.get("name"),
        status="CONFIGURED",
        score=r.get("sensitivity"),
    )


def normalize_sensitive_info_type(r: dict) -> dict:
    """
    Source: Graph beta GET /dataClassification/sensitiveTypes
    owner carries the publisher name (Microsoft vs custom).
    Test signal: NO_RESPONSE means no info types are defined.
    """
    return _build(
        id=r.get("id"),
        service="purview",
        evidenceType="sensitive_info_type",
        name=r.get("name"),
        status="CONFIGURED",
        owner=r.get("publisherName"),
    )


# ── Defender for Endpoint ─────────────────────────────────────────────────────

def normalize_mde_machine(r: dict) -> dict:
    """
    Source: MDE REST GET /api/machines
    COMPLIANT = healthStatus Active AND onboardingStatus Onboarded.
    severity carries MDE's riskScore (Low/Medium/High/None) for risk posture.
    """
    healthy = (
        r.get("healthStatus") == "Active"
        and r.get("onboardingStatus") == "Onboarded"
    )
    return _build(
        id=r.get("id"),
        service="mde",
        evidenceType="machine",
        name=r.get("computerDnsName"),
        status="COMPLIANT" if healthy else "NONCOMPLIANT",
        severity=r.get("riskScore"),
        timestamp=r.get("lastSeen"),
    )


def normalize_mde_alert(r: dict) -> dict:
    """
    Source: MDE REST GET /api/alerts (filtered to high severity)
    Test signal: status == ACTIVE means high-severity threats are open.
    """
    return _build(
        id=r.get("id"),
        service="mde",
        evidenceType="mde_alert",
        name=r.get("title"),
        status="RESOLVED" if r.get("status") == "Resolved" else "ACTIVE",
        severity=r.get("severity"),
        owner=r.get("assignedTo"),
        timestamp=r.get("alertCreationTime"),
    )


def normalize_vulnerability(r: dict) -> dict:
    """
    Source: MDE REST GET /api/vulnerabilities
    affectedCount = exposedMachines (fleet blast radius for this CVE).
    score = cvssV3 for risk scoring in tests.
    """
    return _build(
        id=r.get("id"),
        service="mde",
        evidenceType="vulnerability",
        name=r.get("name"),
        status="ACTIVE",
        severity=r.get("severity"),
        affectedCount=r.get("exposedMachines"),
        score=r.get("cvssV3"),
        timestamp=r.get("publishedOn"),
    )


def normalize_exploit_guard(r: dict) -> dict:
    """
    Source: Graph GET /deviceManagement/deviceConfigurations?$expand=deviceStatusSummary
            filtered to windows10EndpointProtectionConfiguration
    affectedCount = failedDeviceCount — devices where policy failed to apply.
    Test signal: affectedCount > 0 means exploit guard is not fully deployed.
    """
    summary = r.get("deviceStatusSummary") or {}
    return _build(
        id=r.get("id"),
        service="mde",
        evidenceType="exploit_guard",
        name=r.get("displayName"),
        status="CONFIGURED",
        affectedCount=summary.get("failedDeviceCount"),
        timestamp=r.get("lastModifiedDateTime"),
    )


# ── Entra ID Protection ───────────────────────────────────────────────────────

def normalize_risky_user(r: dict) -> dict:
    """
    Source: Graph GET /identityProtection/riskyUsers (pre-filtered to atRisk)
    severity carries riskLevel (high/medium/low) for severity-based thresholds.
    Test signal: any record with status == AT_RISK is a finding.
    """
    return _build(
        id=r.get("id"),
        service="entra_id",
        evidenceType="risky_user",
        name=r.get("userPrincipalName"),
        status=_risk_state(r.get("riskState")),
        severity=r.get("riskLevel"),
        owner=r.get("userDisplayName"),
        timestamp=r.get("riskLastUpdatedDateTime"),
    )


def normalize_risk_detection(r: dict) -> dict:
    """
    Source: Graph GET /identityProtection/riskDetections
    name carries riskType so tests can filter by detection category.
    owner carries userPrincipalName for traceability.
    """
    return _build(
        id=r.get("id"),
        service="entra_id",
        evidenceType="risk_detection",
        name=r.get("riskType"),
        status=_risk_state(r.get("riskState")),
        severity=r.get("riskLevel"),
        owner=r.get("userPrincipalName"),
        timestamp=r.get("detectedDateTime"),
    )


def normalize_risky_principal(r: dict) -> dict:
    """
    Source: Graph GET /identityProtection/riskyServicePrincipals (pre-filtered to atRisk)
    owner carries the appId for cross-referencing the app registration.
    """
    return _build(
        id=r.get("id"),
        service="entra_id",
        evidenceType="risky_principal",
        name=r.get("displayName"),
        status=_risk_state(r.get("riskState")),
        severity=r.get("riskLevel"),
        owner=r.get("appId"),
        timestamp=r.get("riskLastUpdatedDateTime"),
    )


def normalize_named_location(r: dict) -> dict:
    """
    Source: Graph GET /identity/conditionalAccess/namedLocations
    Existence is the evidence — defined locations mean CA network trust
    boundaries are configured.
    Test signal: NO_RESPONSE means no network trust boundaries exist.
    """
    return _build(
        id=r.get("id"),
        service="entra_id",
        evidenceType="named_location",
        name=r.get("displayName"),
        status="CONFIGURED",
        timestamp=r.get("modifiedDateTime"),
    )


# ── Microsoft Intune ──────────────────────────────────────────────────────────

def normalize_device_configuration(r: dict) -> dict:
    """
    Source: Graph GET /deviceManagement/deviceConfigurations?$expand=deviceStatusSummary
    affectedCount = failedDeviceCount (policies not successfully applied).
    Test signal: affectedCount > 0 means devices are not receiving the policy.
    """
    summary = r.get("deviceStatusSummary") or {}
    return _build(
        id=r.get("id"),
        service="intune",
        evidenceType="device_configuration",
        name=r.get("displayName"),
        status="CONFIGURED",
        affectedCount=summary.get("failedDeviceCount"),
        timestamp=r.get("lastModifiedDateTime"),
    )


def normalize_update_ring(r: dict) -> dict:
    """
    Source: Graph GET /deviceManagement/windowsUpdateForBusinessConfigurations
    score = qualityUpdatesDeferralPeriodInDays — directly testable.
    Test signal: score > 7 means quality updates are deferred beyond threshold.
    Test signal: NO_RESPONSE means no patch management policy exists.
    """
    return _build(
        id=r.get("id"),
        service="intune",
        evidenceType="update_ring",
        name=r.get("displayName"),
        status="CONFIGURED",
        score=r.get("qualityUpdatesDeferralPeriodInDays"),
        timestamp=r.get("lastModifiedDateTime"),
    )


def normalize_compliance_policy(r: dict) -> dict:
    """
    Source: Graph GET /deviceManagement/deviceCompliancePolicies
    Existence is the evidence.
    Test signal: NO_RESPONSE means no compliance policies exist.
    """
    return _build(
        id=r.get("id"),
        service="intune",
        evidenceType="compliance_policy",
        name=r.get("displayName"),
        status="CONFIGURED",
        timestamp=r.get("lastModifiedDateTime"),
    )


def normalize_noncompliant_device(r: dict) -> dict:
    """
    Source: Graph GET /deviceManagement/managedDevices
            filtered to complianceState eq 'noncompliant'
    Every record in this resource is a confirmed gap — status is always NONCOMPLIANT.
    Test signal: any record present means noncompliant devices exist.
    Note: NO_RESPONSE is not injected for this resource — an empty list means zero
    noncompliant devices, which is a passing state, not a collection gap.
    """
    return _build(
        id=r.get("id"),
        service="intune",
        evidenceType="noncompliant_device",
        name=r.get("deviceName"),
        status="NONCOMPLIANT",
        owner=r.get("userDisplayName"),
        timestamp=r.get("lastSyncDateTime"),
    )

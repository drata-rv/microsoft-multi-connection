"""
main.py
Suncoast Microsoft compliance data collection and Drata publishing pipeline.

Collects compliance evidence from five Microsoft products via their APIs and
pushes it to a single Drata custom connection using session-based full-replacement
sync. Each resource in the Drata connection mirrors the current state of its
Microsoft source after every run.

Usage:
    python main.py --products all
    python main.py --products sentinel intune
    python main.py --products defender_endpoint --collect-only

    --collect-only  Write compliance_payload.json but do not push to Drata.
                    Useful for verifying API responses before configuring Drata.

--- Required environment variables ---

Microsoft (all products):
    MS_TENANT_ID
    MS_CLIENT_ID
    MS_CLIENT_SECRET

Sentinel (all four required when sentinel is in --products):
    SENTINEL_WORKSPACE_ID        Log Analytics Workspace ID (GUID) for KQL queries
    SENTINEL_SUBSCRIPTION_ID     Azure subscription ID for ARM analytics rules fetch
    SENTINEL_RESOURCE_GROUP      Resource group containing the Sentinel workspace
    SENTINEL_WORKSPACE_NAME      ARM resource name of the workspace

Drata (required unless --collect-only):
    DRATA_API_KEY
    DRATA_CONNECTION_ID          Numeric ID of the custom connection in Drata

Drata resource IDs (numeric; set only for resources created in Drata):
    DRATA_RESOURCE_SENTINEL_INCIDENTS
    DRATA_RESOURCE_SENTINEL_ALERTS
    DRATA_RESOURCE_SENTINEL_RULES
    DRATA_RESOURCE_SENTINEL_THREATS
    DRATA_RESOURCE_PURVIEW_LABELS
    DRATA_RESOURCE_PURVIEW_INFO_TYPES
    DRATA_RESOURCE_MDE_MACHINES
    DRATA_RESOURCE_MDE_ALERTS
    DRATA_RESOURCE_MDE_VULNS
    DRATA_RESOURCE_MDE_EXPLOIT_GUARD
    DRATA_RESOURCE_EID_RISKY_USERS
    DRATA_RESOURCE_EID_RISK_DETECTIONS
    DRATA_RESOURCE_EID_RISKY_PRINCIPALS
    DRATA_RESOURCE_EID_NAMED_LOCATIONS
    DRATA_RESOURCE_INTUNE_CONFIGS
    DRATA_RESOURCE_INTUNE_UPDATE_RINGS
    DRATA_RESOURCE_INTUNE_COMPLIANCE
    DRATA_RESOURCE_INTUNE_NONCOMPLIANT

Any resource ID that is not set is silently skipped. Configure only the resources
that have been created in the Drata app for this connection.

Drata SA Team
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from auth import MSAuthClient
from drata_client import DrataPublisher
import drata_schemas as schemas
from sentinel import SentinelConnector
from purview import PurviewConnector
from defender_endpoint import DefenderEndpointConnector
from defender_identity import DefenderIdentityConnector
from intune import IntuneConnector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

ALL_PRODUCTS = ["sentinel", "purview", "defender_endpoint", "defender_identity", "intune"]

_REQUIRED_MS_VARS = ["MS_TENANT_ID", "MS_CLIENT_ID", "MS_CLIENT_SECRET"]
_SENTINEL_VARS    = [
    "SENTINEL_WORKSPACE_ID",
    "SENTINEL_SUBSCRIPTION_ID",
    "SENTINEL_RESOURCE_GROUP",
    "SENTINEL_WORKSPACE_NAME",
]


# ---------------------------------------------------------------------------
# Resource registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Resource:
    env_var:        str       # env var holding the numeric Drata resourceId
    product:        str       # matches a key in results["products"]
    data_key:       str       # key within the product output dict
    transform:      Callable  # drata_schemas normalizer function
    label:          str       # human label for logging
    service:        str       # schema field — sentinel | purview | mde | entra_id | intune
    evidence_type:  str       # schema field — matches evidenceType in the transform output
    # When True, an empty result list is the passing state (e.g. zero noncompliant
    # devices is good news). Do NOT inject a NO_RESPONSE sentinel in that case.
    no_response_ok: bool = False


_RESOURCE_REGISTRY: list[_Resource] = [
    # ── Sentinel ────────────────────────────────────────────────────────────
    _Resource(
        "DRATA_RESOURCE_SENTINEL_INCIDENTS", "sentinel", "incidents",
        schemas.normalize_incident, "sentinel/incidents",
        "sentinel", "incident",
    ),
    _Resource(
        "DRATA_RESOURCE_SENTINEL_ALERTS", "sentinel", "alerts",
        schemas.normalize_alert, "sentinel/alerts",
        "sentinel", "alert",
    ),
    _Resource(
        "DRATA_RESOURCE_SENTINEL_RULES", "sentinel", "analytics_rules",
        schemas.normalize_analytics_rule, "sentinel/analytics_rules",
        "sentinel", "analytics_rule",
    ),
    _Resource(
        "DRATA_RESOURCE_SENTINEL_THREATS", "sentinel", "threat_detections_summary",
        schemas.normalize_threat_detection, "sentinel/threat_detections",
        "sentinel", "threat_detection",
    ),
    # ── Purview ─────────────────────────────────────────────────────────────
    _Resource(
        "DRATA_RESOURCE_PURVIEW_LABELS", "purview", "sensitivity_labels",
        schemas.normalize_sensitivity_label, "purview/sensitivity_labels",
        "purview", "sensitivity_label",
    ),
    _Resource(
        "DRATA_RESOURCE_PURVIEW_INFO_TYPES", "purview", "sensitive_info_types",
        schemas.normalize_sensitive_info_type, "purview/sensitive_info_types",
        "purview", "sensitive_info_type",
    ),
    # ── Defender for Endpoint ────────────────────────────────────────────────
    _Resource(
        "DRATA_RESOURCE_MDE_MACHINES", "defender_endpoint", "machines",
        schemas.normalize_mde_machine, "mde/machines",
        "mde", "machine",
    ),
    _Resource(
        "DRATA_RESOURCE_MDE_ALERTS", "defender_endpoint", "alerts_high",
        schemas.normalize_mde_alert, "mde/alerts",
        "mde", "mde_alert",
    ),
    _Resource(
        "DRATA_RESOURCE_MDE_VULNS", "defender_endpoint", "software_vulnerabilities",
        schemas.normalize_vulnerability, "mde/vulnerabilities",
        "mde", "vulnerability",
    ),
    _Resource(
        "DRATA_RESOURCE_MDE_EXPLOIT_GUARD", "defender_endpoint", "exploit_guard_policy_coverage",
        schemas.normalize_exploit_guard, "mde/exploit_guard",
        "mde", "exploit_guard",
    ),
    # ── Entra ID Protection ──────────────────────────────────────────────────
    _Resource(
        "DRATA_RESOURCE_EID_RISKY_USERS", "defender_identity", "risky_users",
        schemas.normalize_risky_user, "eid/risky_users",
        "entra_id", "risky_user",
    ),
    _Resource(
        "DRATA_RESOURCE_EID_RISK_DETECTIONS", "defender_identity", "risk_detections",
        schemas.normalize_risk_detection, "eid/risk_detections",
        "entra_id", "risk_detection",
    ),
    _Resource(
        "DRATA_RESOURCE_EID_RISKY_PRINCIPALS", "defender_identity", "risky_service_principals",
        schemas.normalize_risky_principal, "eid/risky_principals",
        "entra_id", "risky_principal",
    ),
    _Resource(
        "DRATA_RESOURCE_EID_NAMED_LOCATIONS", "defender_identity", "named_locations",
        schemas.normalize_named_location, "eid/named_locations",
        "entra_id", "named_location",
    ),
    # ── Intune ───────────────────────────────────────────────────────────────
    _Resource(
        "DRATA_RESOURCE_INTUNE_CONFIGS", "intune", "device_configurations",
        schemas.normalize_device_configuration, "intune/configs",
        "intune", "device_configuration",
    ),
    _Resource(
        "DRATA_RESOURCE_INTUNE_UPDATE_RINGS", "intune", "windows_update_rings",
        schemas.normalize_update_ring, "intune/update_rings",
        "intune", "update_ring",
    ),
    _Resource(
        "DRATA_RESOURCE_INTUNE_COMPLIANCE", "intune", "compliance_policies",
        schemas.normalize_compliance_policy, "intune/compliance_policies",
        "intune", "compliance_policy",
    ),
    # no_response_ok=True: zero noncompliant devices is a passing state.
    # Injecting NO_RESPONSE here would cause false test failures.
    _Resource(
        "DRATA_RESOURCE_INTUNE_NONCOMPLIANT", "intune", "noncompliant_devices",
        schemas.normalize_noncompliant_device, "intune/noncompliant_devices",
        "intune", "noncompliant_device",
        no_response_ok=True,
    ),
]


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_ms_config(products: list[str]) -> dict:
    config  = {k: os.environ.get(k) for k in _REQUIRED_MS_VARS}
    missing = [k for k, v in config.items() if not v]
    if missing:
        logger.error("Missing required Microsoft env vars: %s", missing)
        sys.exit(1)

    if "sentinel" in products:
        sentinel = {k: os.environ.get(k) for k in _SENTINEL_VARS}
        missing_s = [k for k, v in sentinel.items() if not v]
        if missing_s:
            logger.error(
                "sentinel in --products but missing: %s. "
                "Set all four SENTINEL_* vars or exclude sentinel from --products.",
                missing_s,
            )
            sys.exit(1)
        config.update(sentinel)

    return config


def _load_drata_publisher() -> DrataPublisher | None:
    """
    Returns a DrataPublisher if DRATA_API_KEY and DRATA_CONNECTION_ID are set,
    otherwise None (--collect-only mode or env not configured).
    """
    api_key       = os.environ.get("DRATA_API_KEY", "").strip()
    connection_id = os.environ.get("DRATA_CONNECTION_ID", "").strip()

    if not api_key or not connection_id:
        return None

    try:
        return DrataPublisher(api_key=api_key, connection_id=int(connection_id))
    except ValueError:
        logger.error("DRATA_CONNECTION_ID must be a number, got: %s", connection_id)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Product runners
# ---------------------------------------------------------------------------

def _run_sentinel(auth: MSAuthClient, config: dict) -> dict:
    logger.info("Collecting Sentinel data...")
    conn = SentinelConnector(
        auth=auth,
        workspace_id=config["SENTINEL_WORKSPACE_ID"],
        subscription_id=config["SENTINEL_SUBSCRIPTION_ID"],
        resource_group=config["SENTINEL_RESOURCE_GROUP"],
        workspace_name=config["SENTINEL_WORKSPACE_NAME"],
    )
    return {
        "incidents":                 conn.get_incidents(),
        "alerts":                    conn.get_alerts(),
        "analytics_rules":           conn.get_analytics_rules(),
        "threat_detections_summary": conn.get_threat_detections_summary(),
    }


def _run_purview(auth: MSAuthClient) -> dict:
    logger.info("Collecting Purview data...")
    conn = PurviewConnector(auth)
    return {
        "sensitivity_labels":   conn.get_sensitivity_labels(),
        "sensitive_info_types": conn.get_sensitive_info_types(),
    }


def _run_defender_endpoint(auth: MSAuthClient) -> dict:
    logger.info("Collecting Defender for Endpoint data...")
    conn = DefenderEndpointConnector(auth)
    return {
        "machines":                      conn.get_machines(),
        "machines_missing_protection":   conn.get_machines_missing_protection(),
        "alerts_high":                   conn.get_alerts(severity="High"),
        "exposure_score":                conn.get_exposure_score(),
        "software_vulnerabilities":      conn.get_software_vulnerabilities(),
        "exploit_guard_policy_coverage": conn.get_exploit_guard_policy_coverage(),
    }


def _run_defender_identity(auth: MSAuthClient) -> dict:
    logger.info("Collecting Entra ID Protection data...")
    conn = DefenderIdentityConnector(auth)
    return {
        "risky_users":              conn.get_risky_users(),
        "risk_detections":          conn.get_risk_detections(),
        "risky_service_principals": conn.get_risky_service_principals(),
        "risky_sign_ins":           conn.get_risky_sign_ins(),
        "named_locations":          conn.get_conditional_access_named_locations(),
    }


def _run_intune(auth: MSAuthClient) -> dict:
    logger.info("Collecting Intune data...")
    conn = IntuneConnector(auth)
    return {
        "device_configurations":     conn.get_device_configurations(),
        "windows_update_rings":      conn.get_windows_update_rings(),
        "compliance_policies":       conn.get_compliance_policies(),
        "noncompliant_devices":      conn.get_noncompliant_devices(),
        "app_protection_policies":   conn.get_app_protection_policies(),
        "enrollment_configurations": conn.get_enrollment_configurations(),
    }


_RUNNERS = {
    "sentinel":          lambda auth, cfg: _run_sentinel(auth, cfg),
    "purview":           lambda auth, cfg: _run_purview(auth),
    "defender_endpoint": lambda auth, cfg: _run_defender_endpoint(auth),
    "defender_identity": lambda auth, cfg: _run_defender_identity(auth),
    "intune":            lambda auth, cfg: _run_intune(auth),
}


# ---------------------------------------------------------------------------
# Drata publishing
# ---------------------------------------------------------------------------

def _no_response_record(service: str, evidence_type: str) -> dict:
    """
    Synthetic record injected when Microsoft returns no data for a resource.

    Posting this instead of skipping the sync preserves test signal: a custom
    test in Drata can be configured to fail when status == NO_RESPONSE, which
    surfaces collection gaps (empty API responses, revoked permissions) as test
    failures rather than silent passes.

    The stable ID ensures repeated no-data runs upsert rather than accumulate
    duplicate records in Drata.
    """
    return {
        "id":           f"NO_RESPONSE_{service}_{evidence_type}",
        "service":      service,
        "evidenceType": evidence_type,
        "status":       "NO_RESPONSE",
    }


def _publish(publisher: DrataPublisher, results: dict) -> None:
    """
    Iterate the resource registry and publish each configured resource to Drata.

    Resources whose env var is not set are silently skipped — the progressive-
    configuration model means you only configure resources that exist in Drata.

    When Microsoft returns no records and no_response_ok is False, a NO_RESPONSE
    sentinel is injected so downstream tests can surface the gap as a failure.
    """
    publish_errors = 0

    for resource in _RESOURCE_REGISTRY:
        resource_id_str = os.environ.get(resource.env_var, "").strip()
        if not resource_id_str:
            logger.debug("skipping %s — %s not configured", resource.label, resource.env_var)
            continue

        product_data = results["products"].get(resource.product, {})
        if "error" in product_data:
            logger.warning(
                "skipping %s — product %s failed collection",
                resource.label, resource.product,
            )
            continue

        raw = product_data.get(resource.data_key, [])
        if isinstance(raw, dict):
            raw = [raw]

        transformed = [resource.transform(r) for r in raw]

        if not transformed:
            if resource.no_response_ok:
                logger.info(
                    "sync_skipped resource=%s reason=empty_list_is_passing_state",
                    resource.label,
                )
                continue
            else:
                logger.warning(
                    "no_data resource=%s — injecting NO_RESPONSE sentinel",
                    resource.label,
                )
                transformed = [_no_response_record(resource.service, resource.evidence_type)]

        try:
            publisher.sync_resource(
                resource_id=int(resource_id_str),
                records=transformed,
                resource_name=resource.label,
            )
        except Exception as exc:
            logger.error("publish_failed resource=%s error=%s", resource.label, exc)
            publish_errors += 1

    if publish_errors:
        logger.warning("publish_complete with %d resource failure(s)", publish_errors)
    else:
        logger.info("publish_complete all resources synced")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Suncoast Microsoft compliance collector and Drata publisher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--products",
        nargs="+",
        choices=ALL_PRODUCTS + ["all"],
        default=["all"],
        help="Which Microsoft products to collect from.",
    )
    parser.add_argument(
        "--output",
        default="compliance_payload.json",
        help="JSON output file for collected data (always written).",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Collect from Microsoft but skip Drata publishing.",
    )
    args     = parser.parse_args()
    products = ALL_PRODUCTS if "all" in args.products else args.products

    ms_config = _load_ms_config(products)
    auth = MSAuthClient(
        tenant_id=ms_config["MS_TENANT_ID"],
        client_id=ms_config["MS_CLIENT_ID"],
        client_secret=ms_config["MS_CLIENT_SECRET"],
    )

    # ── Collection ────────────────────────────────────────────────────────────
    results: dict = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id":    ms_config["MS_TENANT_ID"],
        "products":     {},
    }

    for product in products:
        try:
            results["products"][product] = _RUNNERS[product](auth, ms_config)
            logger.info("collection_complete product=%s", product)
        except Exception as exc:
            logger.error("collection_failed product=%s error=%s", product, exc, exc_info=True)
            results["products"][product] = {"error": str(exc)}

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("payload_written path=%s", args.output)

    # ── Publishing ────────────────────────────────────────────────────────────
    if args.collect_only:
        logger.info("collect_only mode — skipping Drata publish")
        return

    publisher = _load_drata_publisher()
    if publisher is None:
        logger.warning(
            "DRATA_API_KEY or DRATA_CONNECTION_ID not set — skipping publish. "
            "Run with --collect-only to suppress this warning."
        )
        return

    _publish(publisher, results)


if __name__ == "__main__":
    main()

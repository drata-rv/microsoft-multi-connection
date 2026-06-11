"""
main.py
Suncoast Microsoft compliance data collector.

Collects compliance evidence from five Microsoft products via their APIs and
writes it to a JSON output file. Normalised records (ready for Drata ingestion)
are included alongside the raw API responses.

Usage:
    python main.py --products all
    python main.py --products sentinel intune
    python main.py --products defender_endpoint

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

Drata publish (required unless --collect-only):
    DRATA_API_KEY                API key from Drata Settings → API Keys
    DRATA_CONNECTION_ID          Custom Connection ID
    DRATA_RESOURCE_ID            Resource ID within the connection
                                 (GET /custom-connections/{id}?expand[]=customResources)

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
import drata_schemas as schemas
from drata_publisher import DrataPublisher
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
# Maps each data key to its normaliser. Used to build the normalised output.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Resource:
    product:       str       # matches a key in results["products"]
    data_key:      str       # key within the product output dict
    transform:     Callable  # drata_schemas normalizer function
    label:         str       # human label for logging
    service:       str       # schema field — sentinel | purview | mde | entra_id | intune
    evidence_type: str       # schema field — matches evidenceType in the transform output


_RESOURCE_REGISTRY: list[_Resource] = [
    # ── Sentinel ────────────────────────────────────────────────────────────
    _Resource("sentinel", "incidents",                 schemas.normalize_incident,            "sentinel/incidents",       "sentinel", "incident"),
    _Resource("sentinel", "alerts",                    schemas.normalize_alert,               "sentinel/alerts",          "sentinel", "alert"),
    _Resource("sentinel", "analytics_rules",           schemas.normalize_analytics_rule,      "sentinel/analytics_rules", "sentinel", "analytics_rule"),
    _Resource("sentinel", "threat_detections_summary", schemas.normalize_threat_detection,    "sentinel/threat_detections","sentinel", "threat_detection"),
    # ── Purview ─────────────────────────────────────────────────────────────
    _Resource("purview",  "sensitivity_labels",        schemas.normalize_sensitivity_label,   "purview/sensitivity_labels",   "purview", "sensitivity_label"),
    _Resource("purview",  "sensitive_info_types",      schemas.normalize_sensitive_info_type, "purview/sensitive_info_types", "purview", "sensitive_info_type"),
    # ── Defender for Endpoint ────────────────────────────────────────────────
    _Resource("defender_endpoint", "machines",                      schemas.normalize_mde_machine,   "mde/machines",       "mde", "machine"),
    _Resource("defender_endpoint", "alerts_high",                   schemas.normalize_mde_alert,     "mde/alerts",         "mde", "mde_alert"),
    _Resource("defender_endpoint", "software_vulnerabilities",      schemas.normalize_vulnerability, "mde/vulnerabilities","mde", "vulnerability"),
    _Resource("defender_endpoint", "exploit_guard_policy_coverage", schemas.normalize_exploit_guard, "mde/exploit_guard",  "mde", "exploit_guard"),
    # ── Entra ID Protection ──────────────────────────────────────────────────
    _Resource("defender_identity", "risky_users",              schemas.normalize_risky_user,     "eid/risky_users",       "entra_id", "risky_user"),
    _Resource("defender_identity", "risk_detections",          schemas.normalize_risk_detection, "eid/risk_detections",   "entra_id", "risk_detection"),
    _Resource("defender_identity", "risky_service_principals", schemas.normalize_risky_principal,"eid/risky_principals",  "entra_id", "risky_principal"),
    _Resource("defender_identity", "named_locations",          schemas.normalize_named_location, "eid/named_locations",   "entra_id", "named_location"),
    # ── Intune ───────────────────────────────────────────────────────────────
    _Resource("intune", "device_configurations", schemas.normalize_device_configuration, "intune/configs",           "intune", "device_configuration"),
    _Resource("intune", "windows_update_rings",  schemas.normalize_update_ring,          "intune/update_rings",      "intune", "update_ring"),
    _Resource("intune", "compliance_policies",   schemas.normalize_compliance_policy,    "intune/compliance_policies","intune", "compliance_policy"),
    _Resource("intune", "noncompliant_devices",  schemas.normalize_noncompliant_device,  "intune/noncompliant_devices","intune", "noncompliant_device"),
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


# ---------------------------------------------------------------------------
# Product runners
# ---------------------------------------------------------------------------

def _collect(product: str, calls: list) -> dict:
    out = {}
    for key, fn in calls:
        try:
            result = fn()
            count = len(result) if isinstance(result, list) else 1
            logger.info("call_ok product=%s key=%s records=%d", product, key, count)
            out[key] = result
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status == 403:
                logger.error(
                    "call_failed product=%s key=%s reason=missing_permissions_or_admin_consent status=403",
                    product, key,
                )
            else:
                logger.error("call_failed product=%s key=%s error=%s", product, key, exc)
            out[key] = {"error": str(exc)}
    return out


def _run_sentinel(auth: MSAuthClient, config: dict) -> dict:
    logger.info("Collecting Sentinel data...")
    conn = SentinelConnector(
        auth=auth,
        workspace_id=config["SENTINEL_WORKSPACE_ID"],
        subscription_id=config["SENTINEL_SUBSCRIPTION_ID"],
        resource_group=config["SENTINEL_RESOURCE_GROUP"],
        workspace_name=config["SENTINEL_WORKSPACE_NAME"],
    )
    return _collect("sentinel", [
        ("incidents",                 conn.get_incidents),
        ("alerts",                    conn.get_alerts),
        ("analytics_rules",           conn.get_analytics_rules),
        ("threat_detections_summary", conn.get_threat_detections_summary),
    ])


def _run_purview(auth: MSAuthClient) -> dict:
    logger.info("Collecting Purview data...")
    conn = PurviewConnector(auth)
    return _collect("purview", [
        ("sensitivity_labels",   conn.get_sensitivity_labels),
        ("sensitive_info_types", conn.get_sensitive_info_types),
    ])


def _run_defender_endpoint(auth: MSAuthClient) -> dict:
    logger.info("Collecting Defender for Endpoint data...")
    conn = DefenderEndpointConnector(auth)
    return _collect("defender_endpoint", [
        ("machines",                      conn.get_machines),
        ("alerts_high",                   lambda: conn.get_alerts(severity="High")),
        ("exposure_score",                conn.get_exposure_score),
        ("software_vulnerabilities",      conn.get_software_vulnerabilities),
        ("exploit_guard_policy_coverage", conn.get_exploit_guard_policy_coverage),
    ])


def _run_defender_identity(auth: MSAuthClient) -> dict:
    logger.info("Collecting Entra ID Protection data...")
    conn = DefenderIdentityConnector(auth)
    return _collect("defender_identity", [
        ("risky_users",              conn.get_risky_users),
        ("risk_detections",          conn.get_risk_detections),
        ("risky_service_principals", conn.get_risky_service_principals),
        ("named_locations",          conn.get_conditional_access_named_locations),
    ])


def _run_intune(auth: MSAuthClient) -> dict:
    logger.info("Collecting Intune data...")
    conn = IntuneConnector(auth)
    return _collect("intune", [
        ("device_configurations", conn.get_device_configurations),
        ("windows_update_rings",  conn.get_windows_update_rings),
        ("compliance_policies",   conn.get_compliance_policies),
        ("noncompliant_devices",  conn.get_noncompliant_devices),
    ])


_RUNNERS = {
    "sentinel":          lambda auth, cfg: _run_sentinel(auth, cfg),
    "purview":           lambda auth, cfg: _run_purview(auth),
    "defender_endpoint": lambda auth, cfg: _run_defender_endpoint(auth),
    "defender_identity": lambda auth, cfg: _run_defender_identity(auth),
    "intune":            lambda auth, cfg: _run_intune(auth),
}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def _normalize(results: dict) -> dict:
    """
    Apply drata_schemas normalizers to collected raw data.
    Returns a dict keyed by resource label containing normalised record lists.
    Skips any key where collection failed (product-level or call-level error).
    """
    normalised: dict[str, list] = {}
    for resource in _RESOURCE_REGISTRY:
        product_data = results["products"].get(resource.product, {})
        if "error" in product_data:
            continue
        raw = product_data.get(resource.data_key, [])
        if isinstance(raw, dict) and "error" in raw:
            continue
        if isinstance(raw, dict):
            raw = [raw]
        normalised[resource.label] = [resource.transform(r) for r in raw]
    return normalised


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Suncoast Microsoft compliance collector",
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
        default="/home/compliance_payload.json",
        help="JSON output file for collected data (default: compliance_payload.json).",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Collect from Microsoft and write output file. Skip Drata publish.",
    )
    args     = parser.parse_args()
    products = ALL_PRODUCTS if "all" in args.products else args.products

    ms_config = _load_ms_config(products)
    auth = MSAuthClient(
        tenant_id=ms_config["MS_TENANT_ID"],
        client_id=ms_config["MS_CLIENT_ID"],
        client_secret=ms_config["MS_CLIENT_SECRET"],
    )

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

    results["normalised"] = _normalize(results)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("payload_written path=%s", args.output)

    if args.collect_only:
        logger.info("collect_only — skipping Drata publish")
        return

    drata_vars = ["DRATA_API_KEY", "DRATA_CONNECTION_ID", "DRATA_RESOURCE_ID"]
    missing = [v for v in drata_vars if not os.environ.get(v)]
    if missing:
        logger.error("publish_skipped — missing env vars: %s", missing)
        return

    records = [r for bucket in results["normalised"].values() for r in bucket]
    logger.info("publish_start total_records=%d", len(records))
    try:
        DrataPublisher().publish(records)
    except Exception as exc:
        logger.error("publish_failed error=%s", exc, exc_info=True)


if __name__ == "__main__":
    main()

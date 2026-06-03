"""
main.py
Entry point for the Suncoast Microsoft compliance data collection script.
Runs all connectors and outputs JSON payloads ready for Drata CCT ingestion.

Usage:
    python main.py --products all
    python main.py --products sentinel purview
    python main.py --products defender_endpoint intune

Environment variables (or populate via secrets manager):
    MS_TENANT_ID
    MS_CLIENT_ID
    MS_CLIENT_SECRET
    SENTINEL_WORKSPACE_ID   (required only if sentinel in scope)
    DRATA_API_KEY           (for future CCT push step)
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

from auth import MSAuthClient
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


def load_config() -> dict:
    config = {
        "tenant_id": os.environ.get("MS_TENANT_ID"),
        "client_id": os.environ.get("MS_CLIENT_ID"),
        "client_secret": os.environ.get("MS_CLIENT_SECRET"),
        "sentinel_workspace_id": os.environ.get("SENTINEL_WORKSPACE_ID"),
        "drata_api_key": os.environ.get("DRATA_API_KEY"),
    }
    missing = [k for k, v in config.items()
               if v is None and k not in ("sentinel_workspace_id", "drata_api_key")]
    if missing:
        logger.error("Missing required environment variables: %s", missing)
        sys.exit(1)
    return config


def run_sentinel(auth: MSAuthClient, workspace_id: str) -> dict:
    if not workspace_id:
        logger.error("SENTINEL_WORKSPACE_ID not set. Skipping Sentinel.")
        return {}
    logger.info("Collecting Sentinel data...")
    conn = SentinelConnector(auth, workspace_id)
    return {
        "incidents": conn.get_incidents(),
        "alerts": conn.get_alerts(),
        "analytics_rules": conn.get_analytics_rules(),
        "threat_detections_summary": conn.get_threat_detections_summary(),
    }


def run_purview(auth: MSAuthClient) -> dict:
    logger.info("Collecting Purview data...")
    conn = PurviewConnector(auth)
    return {
        "dlp_policies": conn.get_dlp_policies(),
        "sensitivity_labels": conn.get_sensitivity_labels(),
        "sensitive_info_types": conn.get_sensitive_info_types(),
        "dlp_incidents": conn.get_dlp_incidents(),
    }


def run_defender_endpoint(auth: MSAuthClient) -> dict:
    logger.info("Collecting Defender for Endpoint data...")
    conn = DefenderEndpointConnector(auth)
    return {
        "machines": conn.get_machines(),
        "machines_missing_protection": conn.get_machines_missing_protection(),
        "alerts_high": conn.get_alerts(severity="High"),
        "exposure_score": conn.get_exposure_score(),
        "software_vulnerabilities": conn.get_software_vulnerabilities(),
        "exploit_guard_status": conn.get_exploit_guard_status(),
    }


def run_defender_identity(auth: MSAuthClient) -> dict:
    logger.info("Collecting Defender for Identity data...")
    conn = DefenderIdentityConnector(auth)
    return {
        "risky_users": conn.get_risky_users(),
        "risk_detections": conn.get_risk_detections(),
        "risky_service_principals": conn.get_risky_service_principals(),
        "risky_sign_ins": conn.get_risky_sign_ins(),
        "named_locations": conn.get_conditional_access_named_locations(),
    }


def run_intune(auth: MSAuthClient) -> dict:
    logger.info("Collecting Intune data...")
    conn = IntuneConnector(auth)
    return {
        "device_configurations": conn.get_device_configurations(),
        "windows_update_rings": conn.get_windows_update_rings(),
        "compliance_policies": conn.get_compliance_policies(),
        "noncompliant_devices": conn.get_noncompliant_devices(),
        "app_protection_policies": conn.get_app_protection_policies(),
        "enrollment_configurations": conn.get_enrollment_configurations(),
    }


RUNNERS = {
    "sentinel": lambda auth, cfg: run_sentinel(auth, cfg["sentinel_workspace_id"]),
    "purview": lambda auth, cfg: run_purview(auth),
    "defender_endpoint": lambda auth, cfg: run_defender_endpoint(auth),
    "defender_identity": lambda auth, cfg: run_defender_identity(auth),
    "intune": lambda auth, cfg: run_intune(auth),
}


def main():
    parser = argparse.ArgumentParser(description="Suncoast Microsoft compliance collector")
    parser.add_argument(
        "--products",
        nargs="+",
        choices=ALL_PRODUCTS + ["all"],
        default=["all"],
        help="Which products to collect data from.",
    )
    parser.add_argument(
        "--output",
        default="compliance_payload.json",
        help="Output file for collected data.",
    )
    args = parser.parse_args()

    products = ALL_PRODUCTS if "all" in args.products else args.products
    config = load_config()

    auth = MSAuthClient(
        tenant_id=config["tenant_id"],
        client_id=config["client_id"],
        client_secret=config["client_secret"],
    )

    results = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": config["tenant_id"],
        "products": {},
    }

    for product in products:
        try:
            results["products"][product] = RUNNERS[product](auth, config)
            logger.info("Completed: %s", product)
        except Exception as exc:
            logger.error("Failed collecting %s: %s", product, exc, exc_info=True)
            results["products"][product] = {"error": str(exc)}

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    logger.info("Output written to %s", args.output)


if __name__ == "__main__":
    main()

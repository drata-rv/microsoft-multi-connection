# microsoft-multi-connection

Pulls compliance evidence from five Microsoft products and pushes it to a Drata custom connection. Runs on a schedule, collects everything, syncs to Drata.

---

## Products covered

| Key | What it actually is |
|---|---|
| `sentinel` | Incidents, alerts, analytics rules, threat detections |
| `purview` | Sensitivity labels, sensitive info types |
| `defender_endpoint` | Machines, high alerts, vulns, exploit guard policy coverage |
| `defender_identity` | Risky users, risk detections, risky service principals, named locations (this is Entra ID Protection, not Defender for Identity -- different product, different API) |
| `intune` | Device configs, update rings, compliance policies, noncompliant devices |

---

## Setup

### 1. App Registration

Single Azure AD app registration, client credentials, application permissions (not delegated). See the permissions table below.

| Permission | Why |
|---|---|
| `SecurityEvents.Read.All` | Sentinel incidents and alerts |
| `InformationProtectionPolicy.Read.All` | Purview sensitivity labels |
| `DataClassification.Read.All` | Purview sensitive info types |
| `Machine.Read.All` | MDE machines, vulns, exposure score |
| `Alert.Read.All` | MDE alerts |
| `DeviceManagementManagedDevices.Read.All` | Intune device inventory, noncompliant devices |
| `DeviceManagementConfiguration.Read.All` | Intune config profiles, update rings, exploit guard |
| `IdentityRiskyUser.Read.All` | Entra risky users |
| `IdentityRiskEvent.Read.All` | Entra risk detections |
| `IdentityRiskyServicePrincipal.Read.All` | Entra risky service principals |
| `Policy.Read.All` | Conditional Access named locations |
| `Directory.Read.All` | User and group baseline |

All permissions need admin consent.

### 2. Token scopes

Four API surfaces, four token audiences. `auth.py` handles all of them with the same app registration creds.

| Scope | Used for |
|---|---|
| `https://graph.microsoft.com/.default` | Sentinel, Purview, Intune, Entra ID Protection |
| `https://api.loganalytics.io/.default` | Sentinel KQL queries |
| `https://management.azure.com/.default` | Sentinel analytics rules (ARM) |
| `https://api.securitycenter.microsoft.com/.default` | MDE REST API (will 401 with Graph token) |

### 3. Install

```bash
pip install -r requirements.txt
```

### 4. Environment variables

Copy `.env.example` to `.env` and fill it in.

**Required for all products:**
```
MS_TENANT_ID
MS_CLIENT_ID
MS_CLIENT_SECRET
```

**Required if running sentinel:**
```
SENTINEL_WORKSPACE_ID
SENTINEL_SUBSCRIPTION_ID
SENTINEL_RESOURCE_GROUP
SENTINEL_WORKSPACE_NAME
```

**Required to push to Drata:**
```
DRATA_API_KEY
DRATA_CONNECTION_ID
```

**Drata resource IDs**  set only the ones you want in Drata. Anything unset is skipped silently.
```
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
```

---

## Usage

```bash
# run everything
python main.py --products all

# specific products only
python main.py --products sentinel intune

# collect without pushing to Drata (useful for validating API responses first)
python main.py --products all --collect-only
```

Output is always written to `compliance_payload.json`. Push to Drata happens after unless `--collect-only` is set.

---

## How Drata sync works

Session-based full replacement. Every run opens a session per resource, pushes all current records in batches of 100, then completes the session. Completing the session replaces everything Drata had before with what was just pushed. No state tracking needed locally.

If Microsoft returns zero records for a resource, a `NO_RESPONSE` sentinel record is injected so Drata tests can surface the gap as a failure rather than silently passing. Exception: `noncompliant_devices` where zero records means zero noncompliant devices, which is correct, so nothing is injected.

---

## Note

- A module is named `defender_identity.py` for historical reasons but it talks to Entra ID Protection endpoints, not Defender for Identity.

---

Drata SA Team

# microsoft-multi-connection

Collects compliance evidence from five Microsoft products and writes normalised records to `compliance_payload.json`.

---

## Products covered

| Key | What it actually is |
|---|---|
| `sentinel` | Incidents, alerts, analytics rules, threat detections |
| `purview` | Sensitivity labels, sensitive info types |
| `defender_endpoint` | Machines, high alerts, vulns, exploit guard policy coverage |
| `defender_identity` | Risky users, risk detections, risky service principals, named locations (Entra ID Protection -- not Defender for Identity) |
| `intune` | Device configs, update rings, compliance policies, noncompliant devices |

---

## Setup

### 1. App Registration

Single Azure AD app registration, client credentials, application permissions (not delegated).

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

---

## Usage

```bash
# run everything
python main.py --products all

# specific products only
python main.py --products sentinel intune

# custom output file
python main.py --products all --output my_output.json
```

Output is written to `compliance_payload.json` (or `--output` path). Contains raw API responses and normalised records.

---

## Data schema

The `normalised` key in the output contains records shaped for Drata ingestion. Each record is a JSON object.

Core fields present on every record:

```json
{
  "id": "string",
  "service": "string",
  "evidenceType": "string",
  "name": "string",
  "status": "string",
  "timestamp": "string"
}
```

Shared optional fields (omitted when not applicable -- no nulls):

```json
{
  "severity": "string",
  "owner": "string",
  "affectedCount": 0,
  "score": 0
}
```

Resource-specific fields:

| Resource | Extra fields |
|---|---|
| `machine` | `osPlatform`, `onboardingStatus` |
| `vulnerability` | `publicExploit`, `exploitInKit` |
| `exploit_guard` | `successDeviceCount`, `errorDeviceCount` |
| `device_configuration` | `successDeviceCount`, `errorDeviceCount` |
| `update_ring` | `featureUpdatesDeferralPeriodInDays` |
| `noncompliant_device` | `operatingSystem`, `osVersion` |

`status` values: `ACTIVE`, `ENABLED`, `DISABLED`, `CONFIGURED`, `COMPLIANT`, `NONCOMPLIANT`, `AT_RISK`, `REMEDIATED`, `RESOLVED`, `NO_RESPONSE`, `INVALID`.

---

## Notes

- `defender_identity.py` talks to Entra ID Protection endpoints, not Defender for Identity.
- DLP is out of scope. Purview DLP requires the Office 365 Management Activity API -- separate auth, separate workstream.

---

Drata SA Team

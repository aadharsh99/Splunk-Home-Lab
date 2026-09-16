# DFIR-IRIS Case Management

DFIR-IRIS runs on a separate Debian 13 VM and is used as the case-management platform after Splunk detection. Splunk-to-IRIS case creation is automated through a webhook-based Python bridge; analyst investigation and final resolution remain manual.

## Cases

### Nmap Reconnaissance Against Windows Server
- Status: Closed
- Outcome: True Positive Without Impact
- Resolution: Authorized Lab Activity
- Classification: Information-Gathering: Scanning
- MITRE: T1046 — Network Service Scanning
- Evidence: [`evidence/17_iris_nmap_case_resolved.png`](../evidence/17_iris_nmap_case_resolved.png)

### SMB Enumeration Against Windows Server
- Status: Closed
- Outcome: True Positive Without Impact
- Resolution: Authorized Lab Activity
- Classification: Information-Gathering: Scanning
- Evidence: [`evidence/18_iris_smb_case_resolved.png`](../evidence/18_iris_smb_case_resolved.png)

### Suspicious Whoami Discovery Activity
- Status: Closed
- Outcome: True Positive Without Impact
- Resolution: Authorized Lab Activity
- Classification: Information-Gathering: Scanning
- MITRE: T1033 — System Owner/User Discovery
- Evidence: [`evidence/19_iris_whoami_case_resolved.png`](../evidence/19_iris_whoami_case_resolved.png)

## Workflow

```text
Splunk Detection
      ↓
Analyst Triage
      ↓
DFIR-IRIS Case
      ↓
Investigation / MITRE Mapping
      ↓
Resolution
```

DFIR-IRIS is a case-management layer and is not counted as a telemetry data source.


## Automated Splunk-to-IRIS Case Creation

A Python webhook bridge was used to automate case creation from Splunk detections. The tested workflow is:

```text
Splunk Detection
      ↓
Splunk Webhook
      ↓
Debian 13 Python Bridge
      ↓
DFIR-IRIS Alert
      ↓
DFIR-IRIS Case
      ↓
Analyst Investigation / Resolution
```

The bridge populated the IRIS case with the detection title, MITRE mapping, Splunk search/SID, triggering event data and investigation guidance. Automated cases were created in an initial open/new state so analyst investigation and final resolution remain manual.

### Automated Case Evidence

| Evidence | Description |
|---|---|
| [`evidence/20_iris_nmap_case_automatic_creation.png`](../evidence/20_iris_nmap_case_automatic_creation.png) | Automatically created Nmap case showing Splunk details, MITRE T1046 and investigation guidance |
| [`evidence/21_iris_smb_case_automatic_creation.png`](../evidence/21_iris_smb_case_automatic_creation.png) | Automatically created SMB case showing Splunk details, MITRE T1046 and investigation guidance |
| [`evidence/22_iris_whoami_case_automatic_creation.png`](../evidence/22_iris_whoami_case_automatic_creation.png) | Automatically created Whoami case showing Sysmon Event ID 1, command line, parent process and MITRE T1033 |


### Automation Implementation Evidence

- [`evidence/23_splunk_iris_bridge_running.png`](../evidence/23_splunk_iris_bridge_running.png) — systemd-managed Python webhook bridge with successful IRIS API activity.
- [`evidence/24_iris_bridge_environment_config.png`](../evidence/24_iris_bridge_environment_config.png) — sanitized environment configuration.

## Automated Case Creation and Analyst Investigation

DFIR-IRIS case creation was automated through the Splunk webhook and Python bridge. When a supported detection is received, the bridge creates an IRIS alert and escalates it into a case with the relevant detection metadata, MITRE mapping and triggering event details.

**Case creation is automated; investigation and final resolution are not.** Each automatically created case must still be reviewed by the analyst to validate the alert, examine the available evidence, determine the outcome and complete the final resolution.

## SOC Escalation Workflow

DFIR-IRIS case creation is automated from Splunk detections through the webhook/Python integration. The automatically created case is then triaged and investigated by an **L1 SOC analyst**.

- **L1 SOC:** validates the alert, performs initial triage and investigation, reviews the available evidence, and resolves straightforward authorized/benign cases.
- **L2 SOC:** receives escalation when the case requires deeper investigation, broader scoping, impact analysis, or more complex response actions.
- **L3 SOC:** provides advanced technical analysis and specialist support for complex, novel, or high-impact incidents, including advanced investigation, threat hunting, detection engineering, or major-incident support.

The lab does not implement an L1/L2/L3 escalation mechanism as an automated function. This describes the intended analyst workflow after automatic case creation.


## Actual SOC Workflow in This Lab

**Implemented workflow:**

`Splunk Detection → Automatic IRIS Alert → Automatic IRIS Case Creation → L1 SOC Triage / Investigation → Resolution`

The Splunk webhook and Python bridge automate case creation and populate the IRIS case with detection metadata, MITRE mapping and triggering-event details.

The investigation and final resolution are **not automated**. An L1 SOC analyst validates the alert, reviews available evidence, determines the outcome and resolves straightforward cases.

Where a case cannot be confidently resolved by L1, the professional escalation path is:

`L1 → L2 → L3 (if specialist/advanced analysis is required) → Resolution`

The L1/L2/L3 path describes the intended SOC operating model; the lab does not implement an automated L1/L2/L3 escalation mechanism.

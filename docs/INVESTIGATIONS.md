# Attack Investigations

## Case 01 — Nmap Reconnaissance Against Windows/IIS

### Objective

Identify exposed services and determine whether reconnaissance generated observable telemetry.

### Attack activity

Nmap was used against the Windows target. The scan identified open services including HTTP/80, MSRPC/135, NetBIOS/139 and SMB/445.

### Evidence

- [`evidence/02_nmap_reconnaissance.png`](../evidence/02_nmap_reconnaissance.png)
- [`evidence/03_nmap_splunk_network_telemetry.png`](../evidence/03_nmap_splunk_network_telemetry.png)
- [`evidence/04_iis_http_requests_in_splunk.png`](../evidence/04_iis_http_requests_in_splunk.png)
- [`evidence/15_suricata_sensor_running.png`](../evidence/15_suricata_sensor_running.png)
- [`evidence/16_suricata_nmap_flow_telemetry.png`](../evidence/16_suricata_nmap_flow_telemetry.png)

### Investigation

Splunk Suricata network telemetry shows traffic from the Kali source to the Windows target across multiple destination ports. The IIS search shows HTTP requests reaching port 80, including requests for `/` and `/iisstart.png`.

Suricata provides an independent network-monitoring data source. Its telemetry is visible in Splunk under `sourcetype=suricata`, where the search returns 5,995 events and shows the reconnaissance source `192.168.xxx.xxx` communicating with `192.168.xxx.xxx` across multiple TCP destination ports. Separately, IIS provides web-server/application telemetry showing HTTP requests that reached the web service. These are two independent evidence streams that can be correlated in Splunk.

This demonstrates layered visibility using two independent data sources for this case: Suricata provides network-level flow telemetry, while IIS provides application-layer HTTP evidence.

### Assessment

**Classification:** Network reconnaissance.

**MITRE ATT&CK:** T1046 — Network Service Scanning.

**Analyst takeaway:** network-wide connection patterns are more useful for identifying scanning than relying on a single web-server request.

---

## Case 02 — SMB Share Enumeration

### Objective

Determine whether an external workstation is enumerating Windows SMB resources.

### Attack activity

The attacker used:

```text
smbclient -L //192.168.xxx.xxx -U vboxuser
```

The command enumerated available shares.

### Evidence

- [`evidence/05_smb_enumeration_command.png`](../evidence/05_smb_enumeration_command.png)
- [`evidence/06_smb_security_event_4624.png`](../evidence/06_smb_security_event_4624.png)
- [`evidence/07_smb_enumeration_splunk.png`](../evidence/07_smb_enumeration_splunk.png)
- [`evidence/08_smb_detection_rule.png`](../evidence/08_smb_detection_rule.png)
- [`evidence/09_smb_detection_alert.png`](../evidence/09_smb_detection_alert.png)

### Investigation

Windows Event ID 4624 records a Type 3 network logon associated with the Kali workstation and source address `192.168.xxx.xxx`. Splunk exposes the workstation, source IP, account and authentication package.

The scheduled detection `SMB Enumeration Detected` subsequently triggered, providing an analyst starting point for investigation.

### Assessment

**Classification:** Network share discovery.

**MITRE ATT&CK:** T1135 — Network Share Discovery.

**Recommended response:** validate whether the source system is authorised to access SMB, identify the account used, review adjacent authentication events and investigate additional SMB activity.

---

## Case 03 — Suspicious User Discovery

### Objective

Investigate execution of `whoami /all` and determine the security context of the process.

### Attack activity

The command:

```text
whoami /all
```

was executed on the Windows target.

### Evidence

- [`evidence/10_whoami_execution.png`](../evidence/10_whoami_execution.png)
- [`evidence/11_sysmon_process_creation.png`](../evidence/11_sysmon_process_creation.png)
- [`evidence/12_suspicious_whoami_detection_rule.png`](../evidence/12_suspicious_whoami_detection_rule.png)
- [`evidence/13_suspicious_whoami_detection_alert.png`](../evidence/13_suspicious_whoami_detection_alert.png)
- [`evidence/14_whoami_investigation_splunk.png`](../evidence/14_whoami_investigation_splunk.png)

### Investigation

Sysmon Event ID 1 records `whoami.exe`, its command line, parent process and user. The Splunk investigation extracts these fields and confirms the discovery command.

The evidence shows `whoami.exe /all` with `cmd.exe` as the parent process. This supports a System Owner/User Discovery investigation and does not require PowerShell to be present.

### Assessment

**Classification:** System owner/user discovery.

**MITRE ATT&CK:** T1033 — System Owner/User Discovery.

**Detection improvement:** rename the existing alert to `Suspicious Whoami Discovery Activity` so the detection title directly reflects the observed `whoami.exe /all` behaviour.

---

## Analyst Investigation Checklist

For any future alert in this lab:

- Confirm source and destination.
- Confirm timestamp and sequence of events.
- Identify the account involved.
- Pivot to raw telemetry.
- Review parent/child process relationships.
- Check for related network activity.
- Determine whether the activity is expected.
- Map only the behaviour supported by evidence.
- Document detection gaps and tuning opportunities.


## DFIR-IRIS Case Management

Following the Splunk investigations, each lab scenario was manually documented as a DFIR-IRIS case. The cases were closed as **True Positive Without Impact** and resolved as **Authorized Lab Activity**.

### Nmap Reconnaissance
- Case: `Nmap Reconnaissance Against Windows Server`
- Classification: `Information-Gathering: Scanning`
- MITRE: `T1046 — Network Service Scanning`
- Evidence: [`evidence/17_iris_nmap_case_resolved.png`](../evidence/17_iris_nmap_case_resolved.png)

### SMB Enumeration
- Case: `SMB Enumeration Against Windows Server`
- Classification: `Information-Gathering: Scanning`
- Evidence: [`evidence/18_iris_smb_case_resolved.png`](../evidence/18_iris_smb_case_resolved.png)

### Whoami Discovery
- Case: `Suspicious Whoami Discovery Activity`
- Classification: `Information-Gathering: Scanning`
- MITRE: `T1033 — System Owner/User Discovery`
- Evidence: [`evidence/19_iris_whoami_case_resolved.png`](../evidence/19_iris_whoami_case_resolved.png)

DFIR-IRIS was used manually for case management; Splunk detections are tested by sending Splunk-format webhook payloads to the IRIS automation bridge through the webhook-based Python bridge, while analyst investigation and final resolution remain manual.


## Automated Splunk-to-IRIS Case Creation

The tested automation path creates DFIR-IRIS cases from Splunk detections through a webhook and Python bridge. The resulting cases include the detection, MITRE ATT&CK mapping, Splunk search/SID, triggering result and investigation guidance.

Automated evidence:
- [`evidence/20_iris_nmap_case_automatic_creation.png`](../evidence/20_iris_nmap_case_automatic_creation.png)
- [`evidence/21_iris_smb_case_automatic_creation.png`](../evidence/21_iris_smb_case_automatic_creation.png)
- [`evidence/22_iris_whoami_case_automatic_creation.png`](../evidence/22_iris_whoami_case_automatic_creation.png)

## Resource Constraint Note

Due to the limited system resources available for the lab environment, I was unable to run the full VM stack simultaneously for a live end-to-end Splunk investigation of every scenario. The attack telemetry, Splunk detection evidence, and DFIR-IRIS case workflows were therefore documented using the available lab evidence, while the Splunk-to-IRIS automation was separately validated using Splunk-format webhook payloads.

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

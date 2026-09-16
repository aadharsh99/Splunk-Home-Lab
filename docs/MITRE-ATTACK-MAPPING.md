# MITRE ATT&CK Mapping

## 1. T1046 — Network Service Scanning

**Scenario:** Nmap reconnaissance against the Windows/IIS target.

**Evidence**
- [`evidence/02_nmap_reconnaissance.png`](../evidence/02_nmap_reconnaissance.png)
- [`evidence/03_nmap_splunk_network_telemetry.png`](../evidence/03_nmap_splunk_network_telemetry.png)
- [`evidence/04_iis_http_requests_in_splunk.png`](../evidence/04_iis_http_requests_in_splunk.png)
- [`evidence/16_suricata_nmap_flow_telemetry.png`](../evidence/16_suricata_nmap_flow_telemetry.png)

**Analyst interpretation**

The Nmap scan identifies reachable services on the Windows target, including HTTP, MSRPC, NetBIOS and SMB. Suricata provides independent Suricata network telemetry in Splunk, showing the resulting connection activity and multiple destination ports. IIS separately records HTTP requests that reached the web service. These sources provide distinct network- and application-layer evidence that can be correlated during investigation. No specific Suricata IDS signature alert is claimed from this evidence.

**Detection opportunity:** high-volume or repeated connection attempts across multiple destination ports from a single source host.

---

## 2. T1135 — Network Share Discovery

**Scenario:** SMB share enumeration using `smbclient -L`.

**Evidence**
- [`evidence/05_smb_enumeration_command.png`](../evidence/05_smb_enumeration_command.png)
- [`evidence/06_smb_security_event_4624.png`](../evidence/06_smb_security_event_4624.png)
- [`evidence/07_smb_enumeration_splunk.png`](../evidence/07_smb_enumeration_splunk.png)
- [`evidence/09_smb_detection_alert.png`](../evidence/09_smb_detection_alert.png)

**Analyst interpretation**

The attacker enumerated SMB shares and the Windows host recorded a network logon (Event ID 4624, Logon Type 3) originating from the Kali system. Splunk correlates the endpoint event with the source workstation and source IP.

**Detection opportunity:** unusual network logons to Windows file-sharing services, especially from hosts not normally performing administrative access.

---

## 3. T1033 — System Owner/User Discovery

**Scenario:** `whoami /all` execution on the Windows target.

**Evidence**
- [`evidence/10_whoami_execution.png`](../evidence/10_whoami_execution.png)
- [`evidence/11_sysmon_process_creation.png`](../evidence/11_sysmon_process_creation.png)
- [`evidence/14_whoami_investigation_splunk.png`](../evidence/14_whoami_investigation_splunk.png)

**Analyst interpretation**

`whoami /all` enumerates the current identity, group membership and security context. Sysmon Event ID 1 records the process creation, command line, parent process and user.

**Detection opportunity:** correlate `whoami.exe` with suspicious parent processes, remote sessions or other reconnaissance activity.

---
 
## Detection Engineering Note — Whoami Discovery Alert

The repository contains a scheduled detection named `Suspicious Whoami Discovery Activity`.

The captured Sysmon evidence shows:

- `whoami.exe` as the process
- `cmd.exe` as the parent process
- `whoami /all` as the command line



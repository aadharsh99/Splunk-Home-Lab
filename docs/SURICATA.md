# Suricata Network Sensor

## Role in the Lab

Suricata 8.0.6 was used as an additional network-security telemetry component in the Windows-based lab environment.

The sensor was started in SYSTEM mode and attached to the Windows Npcap capture interface:

```text
suricata.exe -c suricata.yaml -i \\Device\\NPF_{...}
```

The capture interface identifier is intentionally not treated as a security finding; it identifies the interface selected for packet capture.

## Evidence

- [`evidence/15_suricata_sensor_running.png`](../evidence/15_suricata_sensor_running.png)
- [`evidence/16_suricata_nmap_flow_telemetry.png`](../evidence/16_suricata_nmap_flow_telemetry.png)

The first screenshot verifies:

- Suricata version **8.0.6 RELEASE**
- Execution in **SYSTEM mode**
- A configured Npcap capture interface
- Detection-engine threads successfully created
- **Engine started** successfully

The second screenshot provides stronger evidence: Suricata telemetry is present in Splunk under `sourcetype=suricata`. The search returns **5,995 events** and shows traffic from the reconnaissance source `192.168.xxx.xxx` to the Windows target `192.168.xxx.xxx` across multiple TCP destination ports.

This establishes that Suricata was not only running, but that **Suricata-generated network flow telemetry was ingested into Splunk and could be queried during an investigation**.

## Nmap Investigation Correlation

The Suricata telemetry provides network-level visibility for the same reconnaissance activity represented by the Nmap evidence.

The observed fields include:

- `src_ip`
- `dest_ip`
- `dest_port`
- `proto`
- `event_type`

The multiple destination ports observed from one source to the Windows target are consistent with the network activity expected from a service-discovery scan.

Suricata therefore provides a useful network-side investigation pivot. IIS is a separate application-layer data source; the two can be correlated in Splunk but should not be treated as the same telemetry source.

## SOC Value

Suricata is one of four telemetry sources in the lab:

- IIS HTTP logs
- Windows Event Logs
- Sysmon process telemetry
- Suricata network telemetry

Splunk is the analysis platform used to search and correlate these independent sources.

## Evidence Limitation

The available Splunk evidence demonstrates **Suricata flow telemetry ingestion**, not a Suricata IDS signature alert.

Therefore, this repository does **not** claim that Suricata generated a specific IDS alert for the Nmap scan. The evidence supports the more precise conclusion that Suricata captured and forwarded network telemetry that was searchable in Splunk.

If a Suricata `alert` event is added later, it can be documented as a separate detection case with the signature, rule ID, source/destination fields, timestamp and MITRE ATT&CK mapping.

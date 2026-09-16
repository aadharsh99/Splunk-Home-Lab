# Splunk → DFIR-IRIS Automation

The bridge in `splunk_iris_bridge.py` receives Splunk webhook payloads, maps the detection to the appropriate lab case, creates a DFIR-IRIS alert through the REST API, and escalates the alert into an IRIS case.

The implementation supports:
- Nmap reconnaissance → T1046
- SMB enumeration → T1135
- Whoami discovery → T1033
- Medium severity
- New alert status
- Scanning classification
- Automatic case creation
- Splunk SID/search/event details in the IRIS case note

## Configuration

Copy `bridge.env.example` to `bridge.env` on the IRIS Debian 13 VM and replace only the API key with the private value. The numeric IDs are already populated with the validated lab values and are read from the environment by the bridge.

Do not commit `bridge.env` or any real API key to GitHub.

## Runtime

The bridge listens on TCP port `5050` and exposes:
- `GET /health`
- `POST /splunk`

The production lab workflow is:

`Splunk Detection → Webhook → Python Bridge → IRIS Alert → IRIS Case → Analyst Investigation / Resolution`


## Implementation Evidence

| Evidence | Description |
|---|---|
| `evidence/23_splunk_iris_bridge_running.png` | Systemd-managed Python webhook bridge running successfully and showing a successful IRIS API escalation response |
| `evidence/24_iris_bridge_environment_config.png` | Sanitized bridge environment configuration showing IRIS URL and confirmed customer/severity/classification/status IDs |


## Accuracy note

The bridge was validated with Splunk-format webhook payloads generated for the lab scenarios. The implementation demonstrates automated IRIS alert and case creation; it does not claim that all three attack scenarios were simultaneously run through a live Splunk alert in the lab environment.

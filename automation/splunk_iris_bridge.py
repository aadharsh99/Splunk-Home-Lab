import os
import uuid

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

IRIS_URL = os.environ["IRIS_URL"].rstrip("/")
IRIS_API_KEY = os.environ["IRIS_API_KEY"]

def env_int(name, default):
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


CUSTOMER_ID = env_int("IRIS_CUSTOMER_ID", 1)
MEDIUM_SEVERITY_ID = env_int("IRIS_MEDIUM_SEVERITY_ID", 1)
SCANNING_CLASSIFICATION_ID = env_int("IRIS_SCANNING_CLASSIFICATION_ID", 11)
NEW_ALERT_STATUS_ID = env_int("IRIS_ALERT_STATUS_ID", 2)

HEADERS = {
    "Authorization": f"Bearer {IRIS_API_KEY}",
    "Content-Type": "application/json",
}


def iris_post(endpoint, payload):
    url = f"{IRIS_URL}{endpoint}"

    response = requests.post(
        url,
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=20,
    )

    print("\n========================================")
    print("IRIS REQUEST")
    print("========================================")
    print("URL:", url)
    print("HTTP STATUS:", response.status_code)
    print("RESPONSE:", response.text)
    print("========================================\n")

    if response.status_code >= 400:
        raise RuntimeError(
            f"IRIS API returned HTTP {response.status_code}: "
            f"{response.text}"
        )

    return response.json()


def build_case(alert):
    result = alert.get("result") or {}

    search_name = str(
        alert.get("search_name") or ""
    ).lower()

    alert_title = str(
        result.get("alert_title") or ""
    ).lower()

    combined = f"{search_name} {alert_title}"

    if "nmap" in combined or "recon" in combined:
        return {
            "title": "Nmap Reconnaissance Against Windows Server",
            "description": (
                "Nmap reconnaissance was detected against the Windows target. "
                "Review Suricata network telemetry and IIS HTTP evidence in Splunk."
            ),
            "tags": "Nmap,Reconnaissance,T1046,Authorized-Lab",
            "mitre": "T1046 — Network Service Scanning",
        }

    if "smb" in combined or "enumeration" in combined:
        return {
            "title": "SMB Enumeration Against Windows Server",
            "description": (
                "SMB enumeration activity was detected against the Windows target. "
                "Review Windows Event Logs and Sysmon telemetry in Splunk."
            ),
            "tags": "SMB,Enumeration,T1135,Authorized-Lab",
            "mitre": "T1135 — Network Share Discovery",
        }

    return {
        "title": "Suspicious Whoami Discovery Activity",
        "description": (
            "Sysmon Event ID 1 recorded whoami.exe executing whoami /all. "
            "Review the process tree and related Splunk evidence."
        ),
        "tags": "Whoami,Discovery,T1033,Sysmon,Authorized-Lab",
        "mitre": "T1033 — System Owner/User Discovery",
    }


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/splunk")
def splunk_webhook():
    payload = request.get_json(silent=True)

    if not payload:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    result = payload.get("result") or {}
    case = build_case(payload)

    source_ref = payload.get("sid") or f"splunk-{uuid.uuid4()}"

    # Create IRIS alert using the exact payload proven to work.
    alert_payload = {
        "alert_title": case["title"],
        "alert_description": case["description"],
        "alert_source": "Splunk",
        "alert_source_ref": source_ref,
        "alert_severity_id": MEDIUM_SEVERITY_ID,
        "alert_status_id": NEW_ALERT_STATUS_ID,
        "alert_customer_id": CUSTOMER_ID,
        "alert_classification_id": SCANNING_CLASSIFICATION_ID,
    }

    created_alert = iris_post(
        "/alerts/add",
        alert_payload,
    )

    data = created_alert.get("data") or {}
    alert_id = data.get("alert_id")

    if not alert_id:
        return jsonify({
            "error": "IRIS alert was created but no alert_id was returned",
            "iris_response": created_alert,
        }), 502

    # Detailed case note.
    case_note = (
        "### Automated Detection\n\n"
        f"**Detection:** {case['title']}\n\n"
        f"**MITRE ATT&CK:** {case['mitre']}\n\n"
        "### Splunk Details\n\n"
        f"**Search:** {payload.get('search_name', 'N/A')}\n\n"
        f"**SID:** {payload.get('sid', 'N/A')}\n\n"
        f"**Owner:** {payload.get('owner', 'N/A')}\n\n"
        f"**Splunk App:** {payload.get('app', 'N/A')}\n\n"
        f"**Results Link:** {payload.get('results_link', 'N/A')}\n\n"
        "### Triggering Event\n\n"
        f"```text\n{result}\n```\n\n"
        "### Investigation Guidance\n\n"
        f"{case['description']}\n\n"
        "The case was automatically created from a Splunk detection "
        "and requires analyst investigation before resolution."
    )

    # Escalate IRIS alert into an IRIS case.
    escalation_payload = {
        "iocs_import_list": [],
        "assets_import_list": [],
        "note": case_note,
        "import_as_event": True,
        "case_tags": case["tags"],
        "case_title": case["title"],
    }

    case_response = iris_post(
        f"/alerts/escalate/{alert_id}",
        escalation_payload,
    )

    return jsonify({
        "success": True,
        "iris_alert_id": alert_id,
        "iris_case_response": case_response,
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5050,
        debug=False,
    )
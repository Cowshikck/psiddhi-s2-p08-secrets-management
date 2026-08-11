"""
VaultGuard - SOC 2 / ISO 27001 Compliance Mapping Generator (Gemini 2.5 Flash)
Maps VaultGuard audit evidence to specific SOC 2 and ISO 27001 controls.
"""

import json
import os
import time
from datetime import datetime, timezone
from collections import Counter
from dotenv import load_dotenv
import requests

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

AUDIT_LOG_PATH = os.path.join("data", "synthetic", "vault-audit-logs.json")
ANOMALY_REPORT_PATH = os.path.join("data", "anomaly-report.json")
ROTATION_LOG_PATH = os.path.join("data", "rotation-log.json")
POLICY_PATH = os.path.join("data", "rotation-policies.json")

COMPLIANCE_CONTROLS = [
    {
        "id": "SOC2-CC6.1",
        "framework": "SOC 2",
        "control": "CC6.1 - Logical Access Security",
        "requirement": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
        "evidence_type": "access_policy"
    },
    {
        "id": "SOC2-CC6.7",
        "framework": "SOC 2",
        "control": "CC6.7 - Restriction of Data at Rest",
        "requirement": "The entity restricts the transmission, movement, and removal of information to authorised internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives.",
        "evidence_type": "encryption"
    },
    {
        "id": "SOC2-CC7.2",
        "framework": "SOC 2",
        "control": "CC7.2 - Monitoring of System Components",
        "requirement": "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.",
        "evidence_type": "monitoring"
    },
    {
        "id": "ISO27001-A9.2.3",
        "framework": "ISO 27001",
        "control": "A.9.2.3 - Management of Privileged Access Rights",
        "requirement": "The allocation and use of privileged access rights shall be restricted and controlled.",
        "evidence_type": "access_policy"
    },
    {
        "id": "ISO27001-A9.2.4",
        "framework": "ISO 27001",
        "control": "A.9.2.4 - Management of Secret Authentication Information",
        "requirement": "The allocation of secret authentication information shall be controlled through a formal management process including regular rotation.",
        "evidence_type": "rotation"
    },
    {
        "id": "ISO27001-A12.4.1",
        "framework": "ISO 27001",
        "control": "A.12.4.1 - Event Logging",
        "requirement": "Event logs recording user activities, exceptions, faults, and information security events shall be produced, kept, and regularly reviewed.",
        "evidence_type": "monitoring"
    }
]


def load_json_file(path):
    """Load a JSON file, return empty list if not found."""
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


def summarise_audit_logs(entries):
    """Create a statistical summary of audit log entries."""
    total = len(entries)
    by_identity = Counter()
    by_path = Counter()
    by_status = Counter()
    by_operation = Counter()

    for entry in entries:
        by_identity[entry["auth"]["display_name"]] += 1
        by_path[entry["request"]["path"]] += 1
        by_status[entry["response"]["status_code"]] += 1
        by_operation[entry["request"]["operation"]] += 1

    return {
        "total_events": total,
        "by_identity": dict(by_identity.most_common(10)),
        "by_path": dict(by_path.most_common(10)),
        "by_status_code": dict(by_status),
        "by_operation": dict(by_operation),
        "denied_requests": by_status.get(403, 0),
        "successful_requests": by_status.get(200, 0)
    }


def build_evidence_context(control, audit_summary, anomaly_data, rotation_data, policy_data):
    """Build evidence context specific to the control type."""
    context = "System Overview:\n"
    context += "- HashiCorp Vault with KV v2 engine managing 5 secret types\n"
    context += "- 3 identity roles enforced via HCL policies (developer, cicd, platform-admin)\n"
    context += "- Microsoft Entra ID OIDC authentication\n"
    context += "- Automated rotation via GitHub Actions for 3 secret types\n"
    context += "- SOPS + age encryption for 2 environment configs in Git\n"
    context += "- 82 automated tests, 81% code coverage\n\n"

    context += "Audit Log Summary:\n"
    context += "- Total events: " + str(audit_summary["total_events"]) + "\n"
    context += "- Successful (200): " + str(audit_summary["successful_requests"]) + "\n"
    context += "- Denied (403): " + str(audit_summary["denied_requests"]) + "\n\n"

    if control["evidence_type"] == "access_policy":
        context += "Access Policy Evidence:\n"
        context += "- developer: read-only on db-credentials and api-keys paths\n"
        context += "- cicd: read on db-credentials, api-keys, service-tokens, env-config\n"
        context += "- platform-admin: full CRUD on all secret paths + audit + policy read\n"
        context += "- 19 automated policy enforcement tests (allow/deny matrix)\n"
        context += "- Denied requests in audit log: " + str(audit_summary["denied_requests"]) + "\n"
        context += "- Identity distribution: " + json.dumps(audit_summary["by_identity"]) + "\n"

    elif control["evidence_type"] == "rotation":
        context += "Rotation Evidence:\n"
        context += "- 3 secret types rotated: db-credentials, api-keys, service-tokens\n"
        context += "- Rotation schedules: Mon/Wed/Fri at 2am UTC via GitHub Actions\n"
        context += "- Each rotation: generate new value, write to Vault, verify version increment, confirm consumer gets new value, verify old value stale\n"
        context += "- 13 automated rotation tests\n"
        if rotation_data:
            context += "- Recent rotation events: " + str(len(rotation_data)) + "\n"
        if policy_data:
            policies = policy_data.get("policies", [])
            if policies:
                context += "- AI-recommended intervals: "
                for p in policies[:4]:
                    context += p.get("secret_category", "unknown") + " (" + str(p.get("rotation_interval_days", "?")) + "d), "
                context += "\n"

    elif control["evidence_type"] == "encryption":
        context += "Encryption Evidence:\n"
        context += "- SOPS + age asymmetric encryption for config files\n"
        context += "- 2 environment configs encrypted (dev, staging)\n"
        context += "- Private key stored outside repo, gitignored\n"
        context += "- 11 automated SOPS tests including tamper detection\n"
        context += "- Vault KV v2 encrypts secrets at rest in its storage backend\n"
        context += "- HMAC hashing of sensitive values in audit logs\n"

    elif control["evidence_type"] == "monitoring":
        context += "Monitoring Evidence:\n"
        context += "- Vault audit device logs every read, write, auth event as structured JSON\n"
        context += "- Audit logging is synchronous: if log write fails, the request is denied\n"
        context += "- AI anomaly detection: 3 scenarios (off-hours, unusual pairing, frequency burst)\n"
        if isinstance(anomaly_data, dict):
            context += "- Total anomalies detected: " + str(anomaly_data.get("total_anomalies_detected", 0)) + "\n"
            context += "- Anomaly types: " + str(list(anomaly_data.get("anomalies_by_type", {}).keys())) + "\n"
        context += "- Groq AI narrates each anomaly in plain English for security team\n"
        context += "- 14 automated anomaly detection tests\n"

    return context


def generate_control_mapping(control, evidence_context):
    """Generate compliance mapping for a single control using Gemini."""
    prompt = (
        "You are a compliance auditor mapping evidence from a secrets management system "
        "(VaultGuard) to specific compliance framework controls.\n\n"
        "Framework: " + control["framework"] + "\n"
        "Control: " + control["control"] + "\n"
        "Requirement: " + control["requirement"] + "\n\n"
        "Evidence from VaultGuard:\n" + evidence_context + "\n\n"
        "Generate a compliance mapping document with exactly these sections:\n"
        "1. Control Objective: Restate what this control requires in 1-2 sentences.\n"
        "2. Evidence Provided: List specific evidence from VaultGuard that addresses this control. "
        "Be specific — cite numbers, test counts, role names, path restrictions.\n"
        "3. Assessment: State whether the control is Satisfied, Partially Satisfied, or Not Satisfied. "
        "Justify with specific evidence.\n"
        "4. Gaps and Recommendations: If any gaps exist, state them. If the control is fully satisfied, "
        "suggest hardening measures for production.\n\n"
        "Keep it factual. Only reference data provided above. Do not invent metrics. "
        "Use professional audit language. Respond in plain text, not markdown."
    )

    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 2048,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    }

    response = requests.post(GEMINI_URL, headers=headers, params=params, json=body)

    if response.status_code != 200:
        print("  [ERROR] Gemini API returned status " + str(response.status_code))
        return None

    result = response.json()
    parts = result.get("candidates", [{}])[0].get("content", {}).get("parts", [])

    for part in parts:
        if not part.get("thought", False) and part.get("text", ""):
            return part["text"]

    return None


def generate_all_mappings():
    """Generate compliance mappings for all controls."""
    print("Loading data sources...")

    audit_entries = load_json_file(AUDIT_LOG_PATH)
    print("  Audit logs: " + str(len(audit_entries)) + " entries")

    anomaly_data = load_json_file(ANOMALY_REPORT_PATH)
    if isinstance(anomaly_data, list):
        anomaly_data = {}
    print("  Anomaly report: loaded")

    rotation_data = load_json_file(ROTATION_LOG_PATH)
    print("  Rotation log: " + str(len(rotation_data)) + " entries")

    policy_data = load_json_file(POLICY_PATH)
    if isinstance(policy_data, list):
        policy_data = {}
    print("  Rotation policies: loaded")

    audit_summary = summarise_audit_logs(audit_entries)
    print("  Audit summary prepared\n")

    mappings = []

    for i, control in enumerate(COMPLIANCE_CONTROLS):
        if i > 0:
            print("  Waiting 15 seconds for rate limit...")
            time.sleep(15)

        print("[CONTROL] " + control["id"] + " - " + control["control"])

        evidence_context = build_evidence_context(
            control, audit_summary, anomaly_data, rotation_data, policy_data
        )

        mapping_text = generate_control_mapping(control, evidence_context)

        if mapping_text:
            mappings.append({
                "control_id": control["id"],
                "framework": control["framework"],
                "control": control["control"],
                "requirement": control["requirement"],
                "evidence_type": control["evidence_type"],
                "assessment": mapping_text,
                "generated_at": datetime.now(timezone.utc).isoformat()
            })
            print("  [OK] Mapping generated (" + str(len(mapping_text)) + " chars)")
        else:
            print("  [FAIL] No mapping generated")

    return mappings


def save_mappings(mappings):
    """Save compliance mappings as JSON and markdown."""
    output_path = os.path.join("data", "compliance-mapping.json")
    with open(output_path, "w") as f:
        json.dump({
            "title": "VaultGuard - SOC 2 / ISO 27001 Compliance Mapping",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_controls": len(mappings),
            "frameworks": ["SOC 2", "ISO 27001"],
            "mappings": mappings
        }, f, indent=2)
    print("\n[OK] Compliance mapping saved to: " + output_path)

    docs_dir = "docs"
    os.makedirs(docs_dir, exist_ok=True)
    md_path = os.path.join(docs_dir, "compliance_mapping.md")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# VaultGuard - SOC 2 / ISO 27001 Compliance Mapping\n\n")
        f.write("Generated: " + datetime.now(timezone.utc).isoformat() + "\n\n")
        f.write("This document maps VaultGuard's secrets management controls to "
                "specific SOC 2 Trust Service Criteria and ISO 27001 Annex A controls.\n\n")
        f.write("---\n\n")

        for m in mappings:
            f.write("## " + m["control_id"] + " - " + m["control"] + "\n\n")
            f.write("**Framework:** " + m["framework"] + "\n\n")
            f.write("**Requirement:** " + m["requirement"] + "\n\n")
            f.write(m["assessment"] + "\n\n")
            f.write("---\n\n")

    print("[OK] Saved: " + md_path)
    return output_path


if __name__ == "__main__":
    print("=" * 60)
    print("VaultGuard - SOC 2 / ISO 27001 Compliance Mapping Generator")
    print("=" * 60)

    mappings = generate_all_mappings()

    print("\n--- Summary ---")
    print("Total controls mapped: " + str(len(mappings)))
    for m in mappings:
        print("  " + m["control_id"] + " - " + m["control"] + ": OK")

    save_mappings(mappings)
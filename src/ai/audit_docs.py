"""
VaultGuard - AI Audit Trail Documentation Generator (Gemini 2.5 Flash)
Generates compliance-ready audit documentation covering 3 review themes.
"""

import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict, Counter
from dotenv import load_dotenv
import requests

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

AUDIT_LOG_PATH = os.path.join("data", "synthetic", "vault-audit-logs.json")
ANOMALY_REPORT_PATH = os.path.join("data", "anomaly-report.json")
ROTATION_LOG_PATH = os.path.join("data", "rotation-log.json")
POLICY_PATH = os.path.join("data", "rotation-policies.json")

COMPLIANCE_THEMES = [
    {
        "theme": "access_policy_effectiveness",
        "title": "Access Policy Effectiveness Review",
        "description": "Evaluates whether Vault access policies correctly restrict secret access to authorised identities and reject unauthorised attempts."
    },
    {
        "theme": "rotation_compliance",
        "title": "Secret Rotation Compliance Review",
        "description": "Evaluates whether secrets are being rotated according to recommended intervals and whether rotation events complete successfully."
    },
    {
        "theme": "anomaly_response",
        "title": "Anomaly Detection and Response Review",
        "description": "Evaluates the effectiveness of anomaly detection in identifying unusual access patterns and the appropriateness of recommended responses."
    }
]


def load_json_file(path):
    """Load a JSON file, return empty dict/list if not found."""
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


def generate_theme_document(theme_info, audit_summary, anomaly_data, rotation_data, policy_data):
    """Generate a compliance document for a single theme using Gemini."""

    context = (
        "Audit Log Summary:\n"
        + json.dumps(audit_summary, indent=2) + "\n\n"
    )

    if theme_info["theme"] == "access_policy_effectiveness":
        context += (
            "Access Policy Details:\n"
            "- 3 roles configured: developer (read-only on db-creds and api-keys), "
            "cicd (read on db-creds, api-keys, service-tokens, env-config), "
            "platform-admin (full CRUD on all paths)\n"
            "- Denied requests (403): " + str(audit_summary["denied_requests"]) + "\n"
            "- Successful requests (200): " + str(audit_summary["successful_requests"]) + "\n"
        )
    elif theme_info["theme"] == "rotation_compliance":
        context += (
            "Rotation Log:\n"
            + json.dumps(rotation_data[:10], indent=2) + "\n\n"
            "Rotation Policies:\n"
            + json.dumps(policy_data.get("policies", [])[:4], indent=2) + "\n"
        )
    elif theme_info["theme"] == "anomaly_response":
        anomaly_summary = {
            "total_anomalies": anomaly_data.get("total_anomalies_detected", 0),
            "types": list(anomaly_data.get("anomalies_by_type", {}).keys()),
            "ai_narration_excerpt": str(anomaly_data.get("ai_narration", ""))[:500]
        }
        context += (
            "Anomaly Detection Summary:\n"
            + json.dumps(anomaly_summary, indent=2) + "\n"
        )

    prompt = (
        "You are a compliance documentation specialist writing audit trail documentation "
        "for Psiog, a professional digital services firm. Generate a compliance-ready "
        "document for the following review theme.\n\n"
        "Theme: " + theme_info["title"] + "\n"
        "Purpose: " + theme_info["description"] + "\n\n"
        "Data Context:\n" + context + "\n\n"
        "Write a professional compliance document with these sections:\n"
        "1. Executive Summary (2-3 sentences)\n"
        "2. Findings (what the audit data shows)\n"
        "3. Compliance Status (compliant / partially compliant / non-compliant with justification)\n"
        "4. Recommendations (specific actionable items)\n\n"
        "Keep it factual and grounded in the data provided. Do not invent data points. "
        "Use professional compliance language."
    )

    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 4096,
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


def generate_all_documents():
    """Generate audit documentation for all 3 compliance themes."""
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

    documents = {}

    for i, theme in enumerate(COMPLIANCE_THEMES):
        if i > 0:
            print("  Waiting 15 seconds for rate limit...")
            time.sleep(15)
        print("[DOC] Generating: " + theme["title"])
        doc = generate_theme_document(
            theme, audit_summary, anomaly_data, rotation_data, policy_data
        )
        if doc:
            documents[theme["theme"]] = {
                "title": theme["title"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "content": doc
            }
            print("  [OK] Document generated (" + str(len(doc)) + " chars)")
        else:
            print("  [FAIL] No document generated")

    return documents


def save_documents(documents):
    """Save all compliance documents."""
    output_path = os.path.join("data", "audit-documentation.json")
    with open(output_path, "w") as f:
        json.dump(documents, f, indent=2)
    print("\n[OK] Audit documentation saved to: " + output_path)

    docs_dir = "docs"
    os.makedirs(docs_dir, exist_ok=True)

    for theme_key, doc_data in documents.items():
        md_path = os.path.join(docs_dir, theme_key + ".md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# " + doc_data["title"] + "\n\n")
            f.write("Generated: " + doc_data["generated_at"] + "\n\n")
            f.write(doc_data["content"])
        print("[OK] Saved: " + md_path)

    return output_path


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - Audit Documentation Generator")
    print("=" * 50)

    documents = generate_all_documents()

    print("\n--- Summary ---")
    for theme_key, doc_data in documents.items():
        print("  " + doc_data["title"] + ": " + str(len(doc_data["content"])) + " chars")

    save_documents(documents)
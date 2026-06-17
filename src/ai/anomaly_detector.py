"""
VaultGuard - AI Anomaly Detector (Groq - Llama 3.3 70B)
Rule-based pre-filtering + Groq AI narration for detected anomalies.
"""

import json
import os
from datetime import datetime, timezone
from collections import Counter, defaultdict
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
AUDIT_LOG_PATH = os.path.join("data", "synthetic", "vault-audit-logs.json")

OFF_HOURS_START = 22
OFF_HOURS_END = 6
FREQUENCY_THRESHOLD = 20
DEVELOPER_ALLOWED_PATHS = [
    "secret/data/db-credentials/postgres-main",
    "secret/data/api-keys/payment-gateway"
]


def load_audit_logs(path=None):
    """Load audit log entries from JSON file."""
    log_path = path or AUDIT_LOG_PATH
    with open(log_path, "r") as f:
        return json.load(f)


def detect_off_hours_access(entries):
    """Detect human identities accessing secrets outside business hours."""
    flagged = []
    for entry in entries:
        identity = entry["auth"]["display_name"]
        if "cicd" in identity or "github" in identity:
            continue
        timestamp = datetime.fromisoformat(entry["time"])
        hour = timestamp.hour
        if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
            detail = identity + " accessed " + entry["request"]["path"] + " at " + str(hour) + ":00 (outside 06:00-22:00)"
            flagged.append({
                "anomaly_type": "off_hours_access",
                "identity": identity,
                "path": entry["request"]["path"],
                "time": entry["time"],
                "hour": hour,
                "detail": detail
            })
    return flagged


def detect_unusual_pairing(entries):
    """Detect identities accessing secrets outside their normal scope."""
    flagged = []
    for entry in entries:
        identity = entry["auth"]["display_name"]
        path = entry["request"]["path"]
        if "dev" in identity and "developer" in entry["auth"]["policies"]:
            if path not in DEVELOPER_ALLOWED_PATHS:
                detail = identity + " (developer role) accessed " + path + " which is outside developer scope"
                flagged.append({
                    "anomaly_type": "unusual_identity_secret_pairing",
                    "identity": identity,
                    "path": path,
                    "time": entry["time"],
                    "detail": detail
                })
    return flagged


def detect_abnormal_frequency(entries, window_minutes=10):
    """Detect burst access patterns."""
    flagged = []
    by_identity = defaultdict(list)
    for entry in entries:
        identity = entry["auth"]["display_name"]
        by_identity[identity].append(entry)

    for identity, id_entries in by_identity.items():
        id_entries.sort(key=lambda x: x["time"])
        for i, entry in enumerate(id_entries):
            t_start = datetime.fromisoformat(entry["time"])
            t_end_minute = t_start.minute + window_minutes
            if t_end_minute < 60:
                t_end = t_start.replace(minute=t_end_minute)
            else:
                t_end = t_start.replace(hour=t_start.hour + 1, minute=t_end_minute % 60)

            window_count = 0
            for e in id_entries[i:]:
                if datetime.fromisoformat(e["time"]) <= t_end:
                    window_count += 1
                else:
                    break

            if window_count > FREQUENCY_THRESHOLD:
                detail = identity + " made " + str(window_count) + " accesses within " + str(window_minutes) + " minutes starting at " + entry["time"]
                flagged.append({
                    "anomaly_type": "abnormal_access_frequency",
                    "identity": identity,
                    "time": entry["time"],
                    "count_in_window": window_count,
                    "window_minutes": window_minutes,
                    "detail": detail
                })
                break

    return flagged


def run_rule_based_detection(entries):
    """Run all rule-based anomaly detectors."""
    print("[DETECT] Running rule-based anomaly detection...")

    off_hours = detect_off_hours_access(entries)
    print("  Off-hours access: " + str(len(off_hours)) + " flagged")

    unusual = detect_unusual_pairing(entries)
    print("  Unusual identity-secret pairing: " + str(len(unusual)) + " flagged")

    frequency = detect_abnormal_frequency(entries)
    print("  Abnormal access frequency: " + str(len(frequency)) + " flagged")

    all_anomalies = off_hours + unusual + frequency
    print("  Total anomalies detected: " + str(len(all_anomalies)))
    return all_anomalies


def narrate_anomalies_with_groq(anomalies):
    """Send detected anomalies to Groq for plain-English narration."""
    if not anomalies:
        print("[NARRATE] No anomalies to narrate.")
        return None

    client = Groq(api_key=GROQ_API_KEY)

    by_type = defaultdict(list)
    for a in anomalies:
        by_type[a["anomaly_type"]].append(a["detail"])

    anomaly_summary = ""
    for atype, details in by_type.items():
        anomaly_summary += "\n## " + atype + "\n"
        for d in details[:5]:
            anomaly_summary += "- " + d + "\n"
        if len(details) > 5:
            remaining = str(len(details) - 5)
            anomaly_summary += "- ... and " + remaining + " more similar events\n"

    prompt = (
        "You are a security operations analyst reviewing Vault secret access audit logs "
        "for a company called Psiog. The following anomalies were detected by an automated "
        "rule-based system. Write a concise security incident narrative for each anomaly type.\n\n"
        "For each anomaly type, provide:\n"
        "1. **What happened** - describe the anomaly in plain English\n"
        "2. **Risk assessment** - what could this indicate (Low / Medium / High severity)\n"
        "3. **Recommended action** - what the security team should do\n\n"
        "Detected anomalies:\n"
        + anomaly_summary + "\n\n"
        "Write the narrative in a format that a compliance officer or security reviewer can "
        "read and act on. Keep it professional and factual - no speculation beyond what the data shows."
    )

    print("[NARRATE] Sending anomalies to Groq (Llama 3.3 70B)...")
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=1500
    )

    narration = response.choices[0].message.content
    print("[OK] Narration received from Groq.\n")
    return narration


def save_anomaly_report(anomalies, narration):
    """Save the anomaly detection report."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_anomalies_detected": len(anomalies),
        "anomalies_by_type": {},
        "ai_narration": narration
    }

    for a in anomalies:
        atype = a["anomaly_type"]
        if atype not in report["anomalies_by_type"]:
            report["anomalies_by_type"][atype] = []
        report["anomalies_by_type"][atype].append(a)

    output_path = os.path.join("data", "anomaly-report.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print("[OK] Anomaly report saved to: " + output_path)
    return report


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - AI Anomaly Detection")
    print("=" * 50)

    entries = load_audit_logs()
    print("Loaded " + str(len(entries)) + " audit log entries.\n")

    anomalies = run_rule_based_detection(entries)

    print()
    narration = narrate_anomalies_with_groq(anomalies)

    if narration:
        print("--- AI Narration ---")
        print(narration)
        print("---")

    save_anomaly_report(anomalies, narration)
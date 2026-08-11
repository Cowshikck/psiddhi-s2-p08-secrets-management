"""
VaultGuard - Natural Language Audit Query (Groq - Llama 3.3 70B)
Lets users ask plain English questions about Vault audit log data.
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


def load_audit_logs(path=None):
    """Load audit log entries from JSON file."""
    log_path = path or AUDIT_LOG_PATH
    with open(log_path, "r") as f:
        return json.load(f)


def build_audit_context(entries):
    """Build a structured summary of audit data for the AI to query against."""
    total = len(entries)
    by_identity = Counter()
    by_path = Counter()
    by_status = Counter()
    by_operation = Counter()
    by_hour = Counter()
    by_day = Counter()
    identity_paths = defaultdict(set)
    denied_events = []
    off_hours_events = []

    for entry in entries:
        identity = entry["auth"]["display_name"]
        path = entry["request"]["path"]
        status = entry["response"]["status_code"]
        operation = entry["request"]["operation"]
        timestamp = datetime.fromisoformat(entry["time"])

        by_identity[identity] += 1
        by_path[path] += 1
        by_status[status] += 1
        by_operation[operation] += 1
        by_hour[timestamp.hour] += 1
        by_day[timestamp.strftime("%A")] += 1
        identity_paths[identity].add(path)

        if status == 403:
            denied_events.append({
                "identity": identity,
                "path": path,
                "time": entry["time"],
                "operation": operation
            })

        if timestamp.hour >= 22 or timestamp.hour < 6:
            off_hours_events.append({
                "identity": identity,
                "path": path,
                "time": entry["time"],
                "hour": timestamp.hour
            })

    context = "VAULT AUDIT LOG DATA SUMMARY\n"
    context += "============================\n\n"

    context += "OVERVIEW:\n"
    context += "- Total audit events: " + str(total) + "\n"
    context += "- Successful requests (200): " + str(by_status.get(200, 0)) + "\n"
    context += "- Denied requests (403): " + str(by_status.get(403, 0)) + "\n\n"

    context += "IDENTITIES AND ACCESS COUNTS:\n"
    for identity, count in by_identity.most_common():
        paths = sorted(identity_paths[identity])
        context += "- " + identity + ": " + str(count) + " accesses to paths: " + ", ".join(paths) + "\n"
    context += "\n"

    context += "SECRET PATHS AND ACCESS COUNTS:\n"
    for path, count in by_path.most_common():
        context += "- " + path + ": " + str(count) + " accesses\n"
    context += "\n"

    context += "OPERATIONS:\n"
    for op, count in by_operation.most_common():
        context += "- " + op + ": " + str(count) + "\n"
    context += "\n"

    context += "ACCESS BY HOUR OF DAY:\n"
    for hour in sorted(by_hour.keys()):
        context += "- " + str(hour).zfill(2) + ":00 — " + str(by_hour[hour]) + " events\n"
    context += "\n"

    context += "ACCESS BY DAY OF WEEK:\n"
    for day, count in by_day.most_common():
        context += "- " + day + ": " + str(count) + " events\n"
    context += "\n"

    if denied_events:
        context += "DENIED ACCESS ATTEMPTS (403):\n"
        for d in denied_events[:20]:
            context += "- " + d["identity"] + " tried " + d["operation"] + " on " + d["path"] + " at " + d["time"] + "\n"
        if len(denied_events) > 20:
            context += "- ... and " + str(len(denied_events) - 20) + " more\n"
        context += "\n"

    if off_hours_events:
        context += "OFF-HOURS ACCESS (before 06:00 or after 22:00):\n"
        for o in off_hours_events[:20]:
            context += "- " + o["identity"] + " accessed " + o["path"] + " at " + o["time"] + " (hour: " + str(o["hour"]) + ")\n"
        if len(off_hours_events) > 20:
            context += "- ... and " + str(len(off_hours_events) - 20) + " more\n"
        context += "\n"

    context += "POLICY CONFIGURATION:\n"
    context += "- developer: read-only on db-credentials and api-keys\n"
    context += "- cicd: read on db-credentials, api-keys, service-tokens, env-config\n"
    context += "- platform-admin: full CRUD on all paths + audit + policy read\n"

    return context


def query_audit_log(question, audit_context):
    """Send a natural language question to Groq with audit context."""
    client = Groq(api_key=GROQ_API_KEY)

    prompt = (
        "You are a security analyst for Psiog, answering questions about Vault "
        "secret access audit logs. Answer the question below using ONLY the data provided. "
        "Do not invent or assume data that is not present.\n\n"
        "If the data does not contain enough information to answer, say so clearly.\n\n"
        "Be specific — cite exact identities, paths, timestamps, and counts from the data.\n"
        "Keep your answer concise and factual.\n\n"
        + audit_context + "\n\n"
        "QUESTION: " + question + "\n\n"
        "ANSWER:"
    )

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=1000
    )

    return response.choices[0].message.content


def interactive_mode():
    """Run an interactive query session."""
    print("Loading audit logs...")
    entries = load_audit_logs()
    print("Loaded " + str(len(entries)) + " entries.\n")

    print("Building audit context...")
    audit_context = build_audit_context(entries)
    print("Context ready (" + str(len(audit_context)) + " chars).\n")

    print("Type your questions in plain English. Type 'quit' to exit.\n")

    while True:
        question = input("Question: ").strip()
        if not question:
            continue
        if question.lower() in ["quit", "exit", "q"]:
            print("Goodbye.")
            break

        print("\nQuerying Groq...\n")
        answer = query_audit_log(question, audit_context)
        print("Answer: " + answer + "\n")
        print("-" * 50 + "\n")


if __name__ == "__main__":
    print("=" * 60)
    print("VaultGuard - Natural Language Audit Query")
    print("=" * 60 + "\n")
    interactive_mode()
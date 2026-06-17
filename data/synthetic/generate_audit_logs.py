"""
VaultGuard - Synthetic Audit Log Generator
Generates realistic Vault audit log entries including normal access patterns
and deliberate anomalies for AI anomaly detection testing.
"""

import json
import random
import os
from datetime import datetime, timedelta, timezone

# Identity roles
IDENTITIES = {
    "developer": {
        "display_name": "dev-user-alice",
        "policies": ["developer"],
        "normal_hours": (9, 18),  # 9 AM to 6 PM
        "normal_paths": [
            "secret/data/db-credentials/postgres-main",
            "secret/data/api-keys/payment-gateway"
        ]
    },
    "cicd": {
        "display_name": "github-actions-cicd",
        "policies": ["cicd"],
        "normal_hours": (0, 23),  # CI/CD runs anytime
        "normal_paths": [
            "secret/data/db-credentials/postgres-main",
            "secret/data/api-keys/payment-gateway",
            "secret/data/service-tokens/monitoring-agent",
            "secret/data/env-config/dev-settings"
        ]
    },
    "platform-admin": {
        "display_name": "admin-bob",
        "policies": ["platform-admin"],
        "normal_hours": (9, 18),
        "normal_paths": [
            "secret/data/db-credentials/postgres-main",
            "secret/data/api-keys/payment-gateway",
            "secret/data/service-tokens/monitoring-agent",
            "secret/data/tls-certificates/web-frontend",
            "secret/data/env-config/dev-settings"
        ]
    }
}

ALL_SECRET_PATHS = [
    "secret/data/db-credentials/postgres-main",
    "secret/data/api-keys/payment-gateway",
    "secret/data/service-tokens/monitoring-agent",
    "secret/data/tls-certificates/web-frontend",
    "secret/data/env-config/dev-settings"
]

OPERATIONS = ["read", "read", "read", "read", "list"]  # reads are more common


def random_timestamp(base_date, hour_start, hour_end):
    """Generate a random timestamp within a given hour range."""
    hour = random.randint(hour_start, hour_end)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=second, tzinfo=timezone.utc)


def create_audit_entry(identity_key, path, operation, timestamp, is_anomaly=False, anomaly_type=None):
    """Create a single Vault-style audit log entry."""
    identity = IDENTITIES[identity_key]
    
    # Determine if the request was allowed based on policy
    allowed = path in identity["normal_paths"] or identity_key == "platform-admin"
    
    entry = {
        "time": timestamp.isoformat(),
        "type": "request",
        "auth": {
            "display_name": identity["display_name"],
            "policies": identity["policies"],
            "token_type": "service",
            "client_token_accessor": f"accessor_{random.randint(1000, 9999)}"
        },
        "request": {
            "id": f"req_{random.randint(100000, 999999)}",
            "operation": operation,
            "path": path,
            "remote_address": f"10.0.{random.randint(1, 5)}.{random.randint(10, 200)}"
        },
        "response": {
            "status_code": 200 if allowed else 403
        },
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type
    }
    return entry


def generate_normal_entries(num_days=14, entries_per_day=30):
    """Generate normal access pattern entries."""
    entries = []
    base_date = datetime(2026, 6, 1, tzinfo=timezone.utc)

    for day in range(num_days):
        current_date = base_date + timedelta(days=day)

        # Skip weekends for human users — less activity
        is_weekend = current_date.weekday() >= 5

        for _ in range(entries_per_day):
            identity_key = random.choice(list(IDENTITIES.keys()))
            identity = IDENTITIES[identity_key]

            # On weekends, mostly CI/CD
            if is_weekend and identity_key != "cicd" and random.random() > 0.1:
                continue

            path = random.choice(identity["normal_paths"])
            operation = random.choice(OPERATIONS)
            hour_start, hour_end = identity["normal_hours"]
            timestamp = random_timestamp(current_date, hour_start, hour_end)

            entries.append(create_audit_entry(
                identity_key, path, operation, timestamp,
                is_anomaly=False, anomaly_type=None
            ))

    return entries


def generate_anomaly_entries(base_date=None):
    """Generate deliberate anomaly entries for 3 scenarios."""
    if base_date is None:
        base_date = datetime(2026, 6, 10, tzinfo=timezone.utc)

    anomalies = []

    # ANOMALY 1: Off-hours access — developer accessing secrets at 3 AM
    for i in range(5):
        timestamp = random_timestamp(base_date + timedelta(days=i % 3), 1, 4)
        anomalies.append(create_audit_entry(
            "developer",
            random.choice(IDENTITIES["developer"]["normal_paths"]),
            "read",
            timestamp,
            is_anomaly=True,
            anomaly_type="off_hours_access"
        ))

    # ANOMALY 2: Unusual identity-to-secret pairing — developer trying to read TLS certs and service tokens
    for i in range(6):
        timestamp = random_timestamp(base_date + timedelta(days=1), 10, 16)
        unusual_path = random.choice([
            "secret/data/tls-certificates/web-frontend",
            "secret/data/service-tokens/monitoring-agent",
            "secret/data/env-config/dev-settings"
        ])
        anomalies.append(create_audit_entry(
            "developer",
            unusual_path,
            "read",
            timestamp,
            is_anomaly=True,
            anomaly_type="unusual_identity_secret_pairing"
        ))

    # ANOMALY 3: Abnormal access frequency — CI/CD making 50 reads in a short window
    burst_base = base_date + timedelta(days=2)
    for i in range(50):
        timestamp = burst_base.replace(
            hour=14,
            minute=random.randint(0, 5),
            second=random.randint(0, 59),
            tzinfo=timezone.utc
        )
        anomalies.append(create_audit_entry(
            "cicd",
            random.choice(IDENTITIES["cicd"]["normal_paths"]),
            "read",
            timestamp,
            is_anomaly=True,
            anomaly_type="abnormal_access_frequency"
        ))

    return anomalies


def generate_all():
    """Generate complete audit log dataset."""
    print("Generating normal access entries...")
    normal = generate_normal_entries(num_days=14, entries_per_day=30)
    print(f"  Normal entries: {len(normal)}")

    print("Generating anomaly entries...")
    anomalies = generate_anomaly_entries()
    print(f"  Anomaly entries: {len(anomalies)}")

    # Combine and sort by timestamp
    all_entries = normal + anomalies
    all_entries.sort(key=lambda x: x["time"])

    # Save
    output_path = os.path.join("data", "synthetic", "vault-audit-logs.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_entries, f, indent=2)

    print(f"\nTotal entries: {len(all_entries)}")
    print(f"Saved to: {output_path}")

    # Print summary
    anomaly_count = sum(1 for e in all_entries if e["is_anomaly"])
    normal_count = len(all_entries) - anomaly_count
    print(f"\nBreakdown:")
    print(f"  Normal: {normal_count}")
    print(f"  Anomalies: {anomaly_count}")
    print(f"    - off_hours_access: {sum(1 for e in all_entries if e.get('anomaly_type') == 'off_hours_access')}")
    print(f"    - unusual_identity_secret_pairing: {sum(1 for e in all_entries if e.get('anomaly_type') == 'unusual_identity_secret_pairing')}")
    print(f"    - abnormal_access_frequency: {sum(1 for e in all_entries if e.get('anomaly_type') == 'abnormal_access_frequency')}")

    return all_entries


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - Synthetic Audit Log Generator")
    print("=" * 50)
    generate_all()
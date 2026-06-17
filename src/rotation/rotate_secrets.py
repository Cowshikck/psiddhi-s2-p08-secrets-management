"""
VaultGuard - Secret Rotation Logic
Rotates secrets in Vault, verifies propagation, and logs rotation events.
"""

import hvac
import os
import json
import string
import random
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def get_client():
    """Create and return an authenticated Vault client."""
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not client.is_authenticated():
        raise Exception("Vault authentication failed.")
    return client


def generate_password(length=24):
    """Generate a random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choices(chars, k=length))


def generate_api_key(prefix="sk_rotated"):
    """Generate a dummy rotated API key."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
    return f"{prefix}_{suffix}"


def generate_service_token(service_name="service"):
    """Generate a dummy rotated service token."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
    return f"svc_{service_name}_{suffix}"


def read_current_secret(client, path):
    """Read the current version of a secret from Vault."""
    result = client.secrets.kv.v2.read_secret_version(
        path=path,
        mount_point="secret",
        raise_on_deleted_version=True
    )
    return result["data"]["data"], result["data"]["metadata"]["version"]


def write_new_secret(client, path, secret_data):
    """Write a new version of a secret to Vault."""
    result = client.secrets.kv.v2.create_or_update_secret(
        path=path,
        secret=secret_data,
        mount_point="secret"
    )
    return result


def verify_rotation(client, path, expected_version):
    """Verify that the secret was rotated by checking the version incremented."""
    current_data, current_version = read_current_secret(client, path)
    return current_version == expected_version


def log_rotation_event(secret_path, old_version, new_version, status):
    """Log a rotation event to a local JSON log file."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "secret_rotation",
        "secret_path": secret_path,
        "old_version": old_version,
        "new_version": new_version,
        "status": status
    }

    log_file = os.path.join("data", "rotation-log.json")
    os.makedirs("data", exist_ok=True)

    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []

    logs.append(log_entry)

    with open(log_file, "w") as f:
        json.dump(logs, f, indent=2)

    return log_entry


def rotate_db_credentials(client):
    """Rotate database credentials."""
    path = "db-credentials/postgres-main"
    print(f"\n[ROTATE] {path}")

    # Read current
    old_data, old_version = read_current_secret(client, path)
    print(f"  Current version: {old_version}")
    print(f"  Current user: {old_data['username']}")

    # Generate new credentials
    new_data = old_data.copy()
    new_data["password"] = generate_password()
    new_data["rotated_at"] = datetime.now(timezone.utc).isoformat()

    # Write new version
    write_new_secret(client, path, new_data)

    # Verify
    expected_version = old_version + 1
    if verify_rotation(client, path, expected_version):
        log_rotation_event(path, old_version, expected_version, "success")
        print(f"  [OK] Rotated to version {expected_version}")
        return True
    else:
        log_rotation_event(path, old_version, expected_version, "failed")
        print(f"  [FAIL] Rotation verification failed")
        return False


def rotate_api_key(client):
    """Rotate API key."""
    path = "api-keys/payment-gateway"
    print(f"\n[ROTATE] {path}")

    old_data, old_version = read_current_secret(client, path)
    print(f"  Current version: {old_version}")

    new_data = old_data.copy()
    new_data["api_key"] = generate_api_key()
    new_data["rotated_at"] = datetime.now(timezone.utc).isoformat()

    write_new_secret(client, path, new_data)

    expected_version = old_version + 1
    if verify_rotation(client, path, expected_version):
        log_rotation_event(path, old_version, expected_version, "success")
        print(f"  [OK] Rotated to version {expected_version}")
        return True
    else:
        log_rotation_event(path, old_version, expected_version, "failed")
        print(f"  [FAIL] Rotation verification failed")
        return False


def rotate_service_token(client):
    """Rotate service token."""
    path = "service-tokens/monitoring-agent"
    print(f"\n[ROTATE] {path}")

    old_data, old_version = read_current_secret(client, path)
    print(f"  Current version: {old_version}")

    new_data = old_data.copy()
    new_data["token"] = generate_service_token(old_data.get("service", "monitoring"))
    new_data["rotated_at"] = datetime.now(timezone.utc).isoformat()

    write_new_secret(client, path, new_data)

    expected_version = old_version + 1
    if verify_rotation(client, path, expected_version):
        log_rotation_event(path, old_version, expected_version, "success")
        print(f"  [OK] Rotated to version {expected_version}")
        return True
    else:
        log_rotation_event(path, old_version, expected_version, "failed")
        print(f"  [FAIL] Rotation verification failed")
        return False


def rotate_all(client):
    """Rotate all 3 secret types."""
    results = {
        "db-credentials": rotate_db_credentials(client),
        "api-keys": rotate_api_key(client),
        "service-tokens": rotate_service_token(client),
    }

    print("\n--- Rotation Summary ---")
    for secret_type, success in results.items():
        status = "SUCCESS" if success else "FAILED"
        print(f"  {secret_type}: {status}")

    return results


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - Secret Rotation")
    print("=" * 50)

    client = get_client()
    rotate_all(client)
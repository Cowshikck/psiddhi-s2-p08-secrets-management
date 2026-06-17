"""
VaultGuard - Vault Setup Script
Sets up KV v2 engine, stores 5 secret types, enables audit device, and loads HCL policies.
"""

import hvac
import os
import json
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def get_client():
    """Create and return an authenticated Vault client."""
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not client.is_authenticated():
        raise Exception("Vault authentication failed. Check VAULT_TOKEN in .env")
    print("[OK] Vault client authenticated.")
    return client


def setup_kv_engine(client):
    """Enable KV v2 secrets engine at secret/ path (dev mode already has it)."""
    # Dev mode auto-mounts kv at secret/ — verify it exists
    mounts = client.sys.list_mounted_secrets_engines()
    if "secret/" in mounts:
        print("[OK] KV engine already mounted at secret/")
    else:
        client.sys.enable_secrets_engine(
            backend_type="kv",
            path="secret",
            options={"version": "2"}
        )
        print("[OK] KV v2 engine enabled at secret/")


def store_secrets(client):
    """Store 5 distinct secret types in Vault."""

    secrets = {
        "db-credentials/postgres-main": {
            "username": "app_db_user",
            "password": "dummy-postgres-pass-2026",
            "host": "localhost",
            "port": "5432",
            "database": "vaultguard_db"
        },
        "api-keys/payment-gateway": {
            "provider": "stripe",
            "api_key": "sk_test_dummy_payment_key_001",
            "environment": "sandbox"
        },
        "service-tokens/monitoring-agent": {
            "service": "prometheus-agent",
            "token": "svc_token_monitoring_dummy_2026",
            "scope": "read:metrics,write:alerts",
            "expires_at": "2027-01-01T00:00:00Z"
        },
        "tls-certificates/web-frontend": {
            "common_name": "app.vaultguard.dev",
            "certificate": "-----BEGIN CERTIFICATE-----\nDUMMY_CERT_DATA_FOR_POC\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nDUMMY_KEY_DATA_FOR_POC\n-----END PRIVATE KEY-----",
            "expires_at": "2027-06-17T00:00:00Z"
        },
        "env-config/dev-settings": {
            "debug_mode": "true",
            "log_level": "DEBUG",
            "feature_flag_new_ui": "enabled",
            "max_retries": "3",
            "timeout_seconds": "30"
        }
    }

    for path, secret_data in secrets.items():
        client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=secret_data,
            mount_point="secret"
        )
        print(f"[OK] Secret stored: secret/{path}")

    print(f"\n[OK] All {len(secrets)} secret types stored successfully.")


def enable_audit_device(client):
    """Enable file audit device to log all Vault access events."""
    audit_path = os.path.join(os.getcwd(), "vault-audit.log")

    # Check if audit device already enabled
    try:
        existing = client.sys.list_enabled_audit_devices()
        if "file/" in existing:
            print("[OK] Audit device already enabled.")
            return
    except Exception:
        pass

    client.sys.enable_audit_device(
        device_type="file",
        options={"file_path": audit_path}
    )
    print(f"[OK] Audit device enabled. Logging to: {audit_path}")


def load_policies(client):
    """Load HCL policies for 3 identity roles."""

    policies = {
        "developer": """
# Developer policy - read-only access to dev secrets
path "secret/data/db-credentials/*" {
  capabilities = ["read", "list"]
}
path "secret/data/api-keys/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}
""",
        "cicd": """
# CI/CD service principal policy - read access to dev + staging secrets
path "secret/data/db-credentials/*" {
  capabilities = ["read", "list"]
}
path "secret/data/api-keys/*" {
  capabilities = ["read", "list"]
}
path "secret/data/service-tokens/*" {
  capabilities = ["read", "list"]
}
path "secret/data/env-config/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}
""",
        "platform-admin": """
# Platform admin policy - full control on all secret paths
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list", "delete"]
}
path "sys/audit/*" {
  capabilities = ["read", "list", "sudo"]
}
path "sys/policies/*" {
  capabilities = ["read", "list"]
}
"""
    }

    for name, policy in policies.items():
        client.sys.create_or_update_policy(name=name, policy=policy)
        print(f"[OK] Policy loaded: {name}")

    print(f"\n[OK] All {len(policies)} policies loaded successfully.")


def verify_setup(client):
    """Verify everything was set up correctly."""
    print("\n--- Verification ---")

    # Check secrets
    secret_paths = [
        "db-credentials/postgres-main",
        "api-keys/payment-gateway",
        "service-tokens/monitoring-agent",
        "tls-certificates/web-frontend",
        "env-config/dev-settings"
    ]
    for path in secret_paths:
        result = client.secrets.kv.v2.read_secret_version(path=path, mount_point="secret")
        print(f"[OK] Verified: secret/{path} (version {result['data']['metadata']['version']})")

    # Check policies
    for name in ["developer", "cicd", "platform-admin"]:
        policy = client.sys.read_policy(name=name)
        if policy:
            print(f"[OK] Verified: policy '{name}' exists")

    print("\n[DONE] Vault setup complete. 5 secret types + 3 policies + audit device.")


if __name__ == "__main__":
    print("=" * 60)
    print("VaultGuard - Vault Setup")
    print("=" * 60)

    client = get_client()

    print("\n--- Step 1: KV Engine ---")
    setup_kv_engine(client)

    print("\n--- Step 2: Store Secrets ---")
    store_secrets(client)

    print("\n--- Step 3: Audit Device ---")
    enable_audit_device(client)

    print("\n--- Step 4: Load Policies ---")
    load_policies(client)

    verify_setup(client)
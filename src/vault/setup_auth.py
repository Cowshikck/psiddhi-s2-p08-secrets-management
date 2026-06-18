"""
VaultGuard - Auth Setup (Userpass Fallback)
Sets up userpass auth method with 3 identity roles mapped to Vault policies.
This is the documented fallback when Entra ID OIDC access is unavailable.
When Entra ID becomes available, replace userpass with OIDC - the policies remain the same.
"""

import hvac
import os
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

# 3 identity roles matching the proposal
USERS = [
    {
        "username": "alice-developer",
        "password": "dev-pass-2026-demo",
        "policies": ["developer"],
        "role_description": "Developer - read-only access to db-credentials and api-keys"
    },
    {
        "username": "cicd-service",
        "password": "cicd-pass-2026-demo",
        "policies": ["cicd"],
        "role_description": "CI/CD Service Principal - read access to dev + staging secrets"
    },
    {
        "username": "bob-admin",
        "password": "admin-pass-2026-demo",
        "policies": ["platform-admin"],
        "role_description": "Platform Admin - full control on all secret paths"
    }
]


def get_client():
    """Create and return an authenticated Vault client."""
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not client.is_authenticated():
        raise Exception("Vault authentication failed.")
    return client


def enable_userpass(client):
    """Enable userpass auth method if not already enabled."""
    auth_methods = client.sys.list_auth_methods()
    if "userpass/" in auth_methods:
        print("[OK] Userpass auth already enabled.")
        return

    client.sys.enable_auth_method(method_type="userpass")
    print("[OK] Userpass auth method enabled.")


def create_users(client):
    """Create 3 users with mapped policies."""
    for user in USERS:
        client.auth.userpass.create_or_update_user(
            username=user["username"],
            password=user["password"],
            policies=user["policies"]
        )
        print("[OK] User created: " + user["username"] + " -> " + str(user["policies"]))
        print("     " + user["role_description"])


def test_logins(client):
    """Test that each user can log in and gets the correct policies."""
    print("\n--- Login Tests ---")

    for user in USERS:
        try:
            login_response = client.auth.userpass.login(
                username=user["username"],
                password=user["password"]
            )
            token = login_response["auth"]["client_token"]
            attached_policies = login_response["auth"]["policies"]

            # Check policy is attached
            expected_policy = user["policies"][0]
            if expected_policy in attached_policies:
                print("[OK] " + user["username"] + " logged in - policies: " + str(attached_policies))
            else:
                print("[FAIL] " + user["username"] + " missing expected policy: " + expected_policy)

            # Test actual secret access with the user's token
            user_client = hvac.Client(url=VAULT_ADDR, token=token)

            if expected_policy == "developer":
                # Should read db-creds, should NOT read service-tokens
                try:
                    user_client.secrets.kv.v2.read_secret_version(
                        path="db-credentials/postgres-main",
                        mount_point="secret",
                        raise_on_deleted_version=True
                    )
                    print("     [OK] Can read db-credentials (expected)")
                except hvac.exceptions.Forbidden:
                    print("     [FAIL] Cannot read db-credentials (unexpected)")

                try:
                    user_client.secrets.kv.v2.read_secret_version(
                        path="service-tokens/monitoring-agent",
                        mount_point="secret",
                        raise_on_deleted_version=True
                    )
                    print("     [FAIL] Can read service-tokens (should be denied)")
                except hvac.exceptions.Forbidden:
                    print("     [OK] Cannot read service-tokens (expected deny)")

            elif expected_policy == "platform-admin":
                # Should read everything
                try:
                    user_client.secrets.kv.v2.read_secret_version(
                        path="tls-certificates/web-frontend",
                        mount_point="secret",
                        raise_on_deleted_version=True
                    )
                    print("     [OK] Can read tls-certificates (expected for admin)")
                except hvac.exceptions.Forbidden:
                    print("     [FAIL] Cannot read tls-certificates (unexpected)")

        except Exception as e:
            print("[FAIL] " + user["username"] + " login failed: " + str(e))


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - Auth Setup (Userpass Fallback)")
    print("=" * 50)
    print("Note: This is the documented fallback for Entra ID OIDC.")
    print("When Entra ID access is granted, swap userpass for OIDC.\n")

    client = get_client()

    print("--- Step 1: Enable Userpass Auth ---")
    enable_userpass(client)

    print("\n--- Step 2: Create Users ---")
    create_users(client)

    test_logins(client)

    print("\n[DONE] 3 identity roles configured and verified.")
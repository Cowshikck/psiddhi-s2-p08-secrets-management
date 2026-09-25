"""
VaultGuard - Auth Setup (OIDC + Userpass Fallback)
Configures Vault OIDC auth against Entra ID tenant + userpass as fallback.
Run this after every Vault dev mode restart.
"""

import hvac
import os
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

# Entra ID tenant details
TENANT_ID = os.getenv("ENTRA_TENANT_ID")
CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET")
OIDC_DISCOVERY_URL = "https://login.microsoftonline.com/" + TENANT_ID + "/v2.0"

REDIRECT_URIS = [
    "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback"
]

OIDC_ROLES = [
    {"name": "developer", "policies": ["developer"], "description": "Developer - read-only on db-creds and api-keys"},
    {"name": "cicd", "policies": ["cicd"], "description": "CI/CD - read on dev + staging secrets"},
    {"name": "platform-admin", "policies": ["platform-admin"], "description": "Platform Admin - full control"},
]

USERPASS_USERS = [
    {"username": "alice-developer", "password": "dev-pass-2026-demo", "policies": ["developer"]},
    {"username": "cicd-service", "password": "cicd-pass-2026-demo", "policies": ["cicd"]},
    {"username": "bob-admin", "password": "admin-pass-2026-demo", "policies": ["platform-admin"]},
]


def get_client():
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not client.is_authenticated():
        raise Exception("Vault authentication failed.")
    return client


def setup_oidc(client):
    """Enable and configure OIDC auth method against Entra ID."""
    print("--- OIDC Auth (Entra ID) ---")

    # Enable OIDC
    auth_methods = client.sys.list_auth_methods()
    if "oidc/" in auth_methods:
        print("[OK] OIDC auth already enabled.")
    else:
        client.sys.enable_auth_method(method_type="oidc")
        print("[OK] OIDC auth method enabled.")

    # Configure OIDC
    client.auth.oidc.configure(
        oidc_discovery_url=OIDC_DISCOVERY_URL,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret=CLIENT_SECRET,
        default_role="developer"
    )
    print("[OK] OIDC configured against Entra ID tenant: " + TENANT_ID)

    # Create roles
    for role in OIDC_ROLES:
        client.auth.oidc.create_role(
            name=role["name"],
            bound_audiences=[CLIENT_ID],
            allowed_redirect_uris=REDIRECT_URIS,
            user_claim="sub",
            token_policies=role["policies"],
            token_ttl="1h"
        )
        print("[OK] OIDC role: " + role["name"] + " -> " + str(role["policies"]) + " (" + role["description"] + ")")

    print("[OK] OIDC setup complete. Test with: vault login -method=oidc role=developer\n")


def setup_userpass(client):
    """Enable userpass auth as fallback."""
    print("--- Userpass Auth (Fallback) ---")

    auth_methods = client.sys.list_auth_methods()
    if "userpass/" in auth_methods:
        print("[OK] Userpass auth already enabled.")
    else:
        client.sys.enable_auth_method(method_type="userpass")
        print("[OK] Userpass auth method enabled.")

    for user in USERPASS_USERS:
        client.auth.userpass.create_or_update_user(
            username=user["username"],
            password=user["password"],
            policies=user["policies"]
        )
        print("[OK] Userpass user: " + user["username"] + " -> " + str(user["policies"]))

    print("[OK] Userpass setup complete.\n")


def verify(client):
    """Verify both auth methods are configured."""
    print("--- Verification ---")
    auth_methods = client.sys.list_auth_methods()

    if "oidc/" in auth_methods:
        print("[OK] OIDC auth method: enabled")
    else:
        print("[FAIL] OIDC auth method: not found")

    if "userpass/" in auth_methods:
        print("[OK] Userpass auth method: enabled")
    else:
        print("[FAIL] Userpass auth method: not found")

    # Test userpass login
    for user in USERPASS_USERS:
        try:
            login = client.auth.userpass.login(username=user["username"], password=user["password"])
            policies = login["auth"]["policies"]
            print("[OK] Userpass login: " + user["username"] + " -> " + str(policies))
        except Exception as e:
            print("[FAIL] Userpass login: " + user["username"] + " -> " + str(e))

    print("\n[DONE] Both OIDC (Entra ID) and userpass (fallback) auth configured.")
    print("  OIDC test:     vault login -method=oidc role=developer")
    print("  Userpass test:  vault login -method=userpass username=alice-developer password=dev-pass-2026-demo")


if __name__ == "__main__":
    print("=" * 55)
    print("VaultGuard - Auth Setup (OIDC + Userpass)")
    print("=" * 55)
    print("Entra ID Tenant: " + TENANT_ID)
    print("OIDC Client:     " + CLIENT_ID)
    print()

    client = get_client()
    setup_oidc(client)
    setup_userpass(client)
    verify(client)
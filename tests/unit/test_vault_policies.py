"""
VaultGuard - Policy Enforcement Tests
Tests the allow/deny matrix: each role x each secret path.
"""

import hvac
import pytest
import os
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def create_token_for_policy(policy_name):
    """Create a Vault token attached to a specific policy."""
    root_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    result = root_client.auth.token.create(policies=[policy_name], ttl="5m")
    return result["auth"]["client_token"]


def read_secret(token, path):
    """Attempt to read a secret with the given token. Returns True if allowed, False if denied."""
    client = hvac.Client(url=VAULT_ADDR, token=token)
    try:
        client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point="secret",
            raise_on_deleted_version=True
        )
        return True
    except hvac.exceptions.Forbidden:
        return False


def write_secret(token, path, data):
    """Attempt to write a secret with the given token. Returns True if allowed, False if denied."""
    client = hvac.Client(url=VAULT_ADDR, token=token)
    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=data,
            mount_point="secret"
        )
        return True
    except hvac.exceptions.Forbidden:
        return False


# --- Developer Role Tests ---

class TestDeveloperPolicy:
    """Developer should: read db-credentials and api-keys. Cannot: read service-tokens, tls-certs, env-config. Cannot: write anything."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.token = create_token_for_policy("developer")

    def test_can_read_db_credentials(self):
        assert read_secret(self.token, "db-credentials/postgres-main") is True

    def test_can_read_api_keys(self):
        assert read_secret(self.token, "api-keys/payment-gateway") is True

    def test_cannot_read_service_tokens(self):
        assert read_secret(self.token, "service-tokens/monitoring-agent") is False

    def test_cannot_read_tls_certificates(self):
        assert read_secret(self.token, "tls-certificates/web-frontend") is False

    def test_cannot_read_env_config(self):
        assert read_secret(self.token, "env-config/dev-settings") is False

    def test_cannot_write_db_credentials(self):
        assert write_secret(self.token, "db-credentials/test-write", {"test": "value"}) is False


# --- CI/CD Role Tests ---

class TestCicdPolicy:
    """CI/CD should: read db-credentials, api-keys, service-tokens, env-config. Cannot: read tls-certs. Cannot: write anything."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.token = create_token_for_policy("cicd")

    def test_can_read_db_credentials(self):
        assert read_secret(self.token, "db-credentials/postgres-main") is True

    def test_can_read_api_keys(self):
        assert read_secret(self.token, "api-keys/payment-gateway") is True

    def test_can_read_service_tokens(self):
        assert read_secret(self.token, "service-tokens/monitoring-agent") is True

    def test_can_read_env_config(self):
        assert read_secret(self.token, "env-config/dev-settings") is True

    def test_cannot_read_tls_certificates(self):
        assert read_secret(self.token, "tls-certificates/web-frontend") is False

    def test_cannot_write_db_credentials(self):
        assert write_secret(self.token, "db-credentials/test-write", {"test": "value"}) is False


# --- Platform Admin Role Tests ---

class TestPlatformAdminPolicy:
    """Platform admin should: read and write everything."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.token = create_token_for_policy("platform-admin")

    def test_can_read_db_credentials(self):
        assert read_secret(self.token, "db-credentials/postgres-main") is True

    def test_can_read_api_keys(self):
        assert read_secret(self.token, "api-keys/payment-gateway") is True

    def test_can_read_service_tokens(self):
        assert read_secret(self.token, "service-tokens/monitoring-agent") is True

    def test_can_read_tls_certificates(self):
        assert read_secret(self.token, "tls-certificates/web-frontend") is True

    def test_can_read_env_config(self):
        assert read_secret(self.token, "env-config/dev-settings") is True

    def test_can_write_db_credentials(self):
        assert write_secret(self.token, "db-credentials/test-admin-write", {"test": "admin"}) is True

    def test_can_write_new_secret(self):
        assert write_secret(self.token, "api-keys/test-admin-new", {"key": "new"}) is True
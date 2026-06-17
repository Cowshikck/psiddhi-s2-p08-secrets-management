"""
VaultGuard - Dummy Consumer Service
Simulates a service that reads secrets from Vault and "uses" them.
Used to verify rotation propagation — after rotation, consumer must get the new value.
"""

import hvac
import os
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


class DummyConsumer:
    """Simulates a service that depends on a Vault secret."""

    def __init__(self, name, secret_path, key_field):
        self.name = name
        self.secret_path = secret_path
        self.key_field = key_field
        self.client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        self.cached_value = None

    def fetch_secret(self):
        """Fetch the current secret value from Vault."""
        result = self.client.secrets.kv.v2.read_secret_version(
            path=self.secret_path,
            mount_point="secret",
            raise_on_deleted_version=True
        )
        data = result["data"]["data"]
        version = result["data"]["metadata"]["version"]
        self.cached_value = data[self.key_field]
        return self.cached_value, version

    def authenticate(self):
        """Simulate authenticating with the current secret."""
        value, version = self.fetch_secret()
        print(f"  [{self.name}] Authenticated with version {version}: {value[:20]}...")
        return True

    def has_stale_credential(self, old_value):
        """Check if the consumer still holds a stale (pre-rotation) credential."""
        current_value, _ = self.fetch_secret()
        return current_value == old_value


# Pre-configured consumers for each secret type
def get_db_consumer():
    return DummyConsumer("db-app", "db-credentials/postgres-main", "password")


def get_api_consumer():
    return DummyConsumer("api-app", "api-keys/payment-gateway", "api_key")


def get_token_consumer():
    return DummyConsumer("monitor-app", "service-tokens/monitoring-agent", "token")


if __name__ == "__main__":
    print("--- Dummy Consumer Check ---")
    for consumer in [get_db_consumer(), get_api_consumer(), get_token_consumer()]:
        consumer.authenticate()
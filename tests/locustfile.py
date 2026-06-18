"""
VaultGuard - Load Testing with Locust
Tests Vault audit pipeline throughput under simulated burst access.
Make sure Vault is running in dev mode and setup_vault.py has been executed.
"""

import json
import time
import random
from locust import User, task, between, events

import hvac
import os
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

SECRET_PATHS = [
    "db-credentials/postgres-main",
    "api-keys/payment-gateway",
    "service-tokens/monitoring-agent",
    "tls-certificates/web-frontend",
    "env-config/dev-settings"
]


class VaultUser(User):
    """Simulates users reading secrets from Vault."""

    wait_time = between(0.1, 0.5)

    def on_start(self):
        """Create a Vault client when the user starts."""
        self.client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

    @task(5)
    def read_random_secret(self):
        """Read a random secret from Vault."""
        path = random.choice(SECRET_PATHS)
        start_time = time.time()
        try:
            result = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point="secret",
                raise_on_deleted_version=True
            )
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_READ",
                name="read/" + path,
                response_time=total_time,
                response_length=len(json.dumps(result["data"]["data"])),
                exception=None
            )
        except Exception as e:
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_READ",
                name="read/" + path,
                response_time=total_time,
                response_length=0,
                exception=e
            )

    @task(2)
    def list_secrets(self):
        """List secrets at a path."""
        start_time = time.time()
        try:
            result = self.client.secrets.kv.v2.list_secrets(
                path="",
                mount_point="secret"
            )
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_LIST",
                name="list/secret",
                response_time=total_time,
                response_length=len(str(result)),
                exception=None
            )
        except Exception as e:
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_LIST",
                name="list/secret",
                response_time=total_time,
                response_length=0,
                exception=e
            )

    @task(1)
    def write_and_read_secret(self):
        """Simulate a rotation-like write then read."""
        path = "load-test/temp-secret-" + str(random.randint(1, 100))
        start_time = time.time()
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={"value": "load-test-" + str(time.time())},
                mount_point="secret"
            )
            self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point="secret",
                raise_on_deleted_version=True
            )
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_WRITE_READ",
                name="write_read/" + path,
                response_time=total_time,
                response_length=0,
                exception=None
            )
        except Exception as e:
            total_time = (time.time() - start_time) * 1000
            events.request.fire(
                request_type="VAULT_WRITE_READ",
                name="write_read/" + path,
                response_time=total_time,
                response_length=0,
                exception=e
            )
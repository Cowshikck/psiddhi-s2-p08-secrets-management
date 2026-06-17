"""
VaultGuard - Rotation Tests
Tests rotation logic, version increment, consumer propagation, and stale credential detection.
"""

import pytest
import os
import json
from dotenv import load_dotenv
from src.rotation.rotate_secrets import (
    get_client, read_current_secret, rotate_db_credentials,
    rotate_api_key, rotate_service_token, generate_password,
    generate_api_key, generate_service_token
)
from src.rotation.dummy_consumer import get_db_consumer, get_api_consumer, get_token_consumer

load_dotenv()


class TestGenerators:
    """Test that credential generators produce valid values."""

    def test_password_length(self):
        pwd = generate_password(24)
        assert len(pwd) == 24

    def test_password_randomness(self):
        p1 = generate_password()
        p2 = generate_password()
        assert p1 != p2

    def test_api_key_has_prefix(self):
        key = generate_api_key("sk_rotated")
        assert key.startswith("sk_rotated_")

    def test_service_token_has_prefix(self):
        token = generate_service_token("monitoring")
        assert token.startswith("svc_monitoring_")


class TestDBCredentialRotation:
    """Test database credential rotation end-to-end."""

    def test_rotation_increments_version(self):
        client = get_client()
        _, version_before = read_current_secret(client, "db-credentials/postgres-main")
        result = rotate_db_credentials(client)
        _, version_after = read_current_secret(client, "db-credentials/postgres-main")
        assert result is True
        assert version_after == version_before + 1

    def test_consumer_gets_new_value(self):
        client = get_client()
        consumer = get_db_consumer()
        old_value, _ = consumer.fetch_secret()

        rotate_db_credentials(client)

        new_value, _ = consumer.fetch_secret()
        assert new_value != old_value

    def test_consumer_no_stale_credential(self):
        client = get_client()
        consumer = get_db_consumer()
        old_value, _ = consumer.fetch_secret()

        rotate_db_credentials(client)

        assert consumer.has_stale_credential(old_value) is False


class TestAPIKeyRotation:
    """Test API key rotation end-to-end."""

    def test_rotation_increments_version(self):
        client = get_client()
        _, version_before = read_current_secret(client, "api-keys/payment-gateway")
        result = rotate_api_key(client)
        _, version_after = read_current_secret(client, "api-keys/payment-gateway")
        assert result is True
        assert version_after == version_before + 1

    def test_consumer_gets_new_value(self):
        client = get_client()
        consumer = get_api_consumer()
        old_value, _ = consumer.fetch_secret()

        rotate_api_key(client)

        new_value, _ = consumer.fetch_secret()
        assert new_value != old_value


class TestServiceTokenRotation:
    """Test service token rotation end-to-end."""

    def test_rotation_increments_version(self):
        client = get_client()
        _, version_before = read_current_secret(client, "service-tokens/monitoring-agent")
        result = rotate_service_token(client)
        _, version_after = read_current_secret(client, "service-tokens/monitoring-agent")
        assert result is True
        assert version_after == version_before + 1

    def test_consumer_gets_new_value(self):
        client = get_client()
        consumer = get_token_consumer()
        old_value, _ = consumer.fetch_secret()

        rotate_service_token(client)

        new_value, _ = consumer.fetch_secret()
        assert new_value != old_value


class TestRotationLog:
    """Test that rotation events are logged."""

    def test_log_file_created(self):
        client = get_client()
        rotate_db_credentials(client)
        assert os.path.exists(os.path.join("data", "rotation-log.json"))

    def test_log_contains_entries(self):
        log_file = os.path.join("data", "rotation-log.json")
        with open(log_file, "r") as f:
            logs = json.load(f)
        assert len(logs) > 0
        assert logs[-1]["event"] == "secret_rotation"
        assert logs[-1]["status"] == "success"
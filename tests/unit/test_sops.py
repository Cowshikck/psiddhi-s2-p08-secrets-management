"""
VaultGuard - SOPS Integrity Tests
Tests encrypt/decrypt roundtrip, config loading, and tamper detection.
"""

import pytest
import os
import tempfile
import shutil
import subprocess
from src.sops.config_loader import decrypt_config, load_environment_config, get_config_value

SOPS_PATH = r"C:\Users\cowshik.eswaramoorth\vault\sops.exe"
AGE_PUBLIC_KEY = "age1mjehny0mqgfnfxcwxc9ddmvdnk8k8xmkz0aaq7ler4wmj3sl5auq7xa2ml"


class TestSOPSDecrypt:
    """Test that SOPS-encrypted configs decrypt correctly."""

    def test_dev_config_decrypts(self):
        config = load_environment_config("dev")
        assert config is not None
        assert isinstance(config, dict)

    def test_staging_config_decrypts(self):
        config = load_environment_config("staging")
        assert config is not None
        assert isinstance(config, dict)

    def test_dev_config_has_expected_structure(self):
        config = load_environment_config("dev")
        assert "app" in config
        assert "database" in config
        assert "api" in config
        assert "features" in config

    def test_staging_config_has_expected_structure(self):
        config = load_environment_config("staging")
        assert "app" in config
        assert "database" in config
        assert "api" in config
        assert "features" in config


class TestSOPSRoundtrip:
    """Test that encrypting then decrypting returns original values."""

    def test_dev_roundtrip_values(self):
        config = load_environment_config("dev")
        assert get_config_value(config, "app", "name") == "vaultguard"
        assert get_config_value(config, "app", "environment") == "dev"
        assert get_config_value(config, "database", "host") == "localhost"
        assert get_config_value(config, "database", "port") == 5432
        assert get_config_value(config, "database", "password") == "dev-dummy-password-2026"

    def test_staging_roundtrip_values(self):
        config = load_environment_config("staging")
        assert get_config_value(config, "app", "name") == "vaultguard"
        assert get_config_value(config, "app", "environment") == "staging"
        assert get_config_value(config, "database", "host") == "staging-db.internal"
        assert get_config_value(config, "database", "password") == "staging-dummy-password-2026"


class TestSOPSTamperDetection:
    """Test that tampered encrypted files fail to decrypt."""

    def test_tampered_file_fails(self):
        # Copy encrypted file to temp location
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "tampered.enc.yaml")
        shutil.copy("configs/dev/config.enc.yaml", temp_file)

        # Tamper with the file — modify an encrypted value
        with open(temp_file, "r") as f:
            content = f.read()

        # Corrupt the MAC to trigger SOPS integrity check failure
        content = content.replace("mac: ENC[AES256_GCM,", "mac: ENC[AES256_GCM,data:CORRUPTED,")

        with open(temp_file, "w") as f:
            f.write(content)

        # Decryption should fail
        with pytest.raises(RuntimeError, match="SOPS decrypt failed"):
            decrypt_config(temp_file)

        # Cleanup
        shutil.rmtree(temp_dir)


class TestSOPSFileNotFound:
    """Test error handling for missing files."""

    def test_missing_file_raises_error(self):
        with pytest.raises(FileNotFoundError):
            decrypt_config("configs/nonexistent/config.enc.yaml")


class TestConfigValueHelper:
    """Test the get_config_value utility."""

    def test_nested_value(self):
        config = {"a": {"b": {"c": "deep"}}}
        assert get_config_value(config, "a", "b", "c") == "deep"

    def test_missing_key_returns_none(self):
        config = {"a": {"b": 1}}
        assert get_config_value(config, "a", "x") is None

    def test_empty_config_returns_none(self):
        assert get_config_value({}, "a") is None
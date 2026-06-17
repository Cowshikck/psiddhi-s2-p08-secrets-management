"""
VaultGuard - SOPS Config Loader
Decrypts SOPS-encrypted config files and loads them into a dictionary.
"""

import subprocess
import yaml
import os
from dotenv import load_dotenv

load_dotenv()

SOPS_PATH = r"C:\Users\cowshik.eswaramoorth\vault\sops.exe"
SOPS_AGE_KEY_FILE = os.getenv("SOPS_AGE_KEY_FILE", r"C:\Users\cowshik.eswaramoorth\vault\key.txt")


def decrypt_config(encrypted_file_path):
    """Decrypt a SOPS-encrypted YAML file and return as a Python dictionary."""
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted config not found: {encrypted_file_path}")

    env = os.environ.copy()
    env["SOPS_AGE_KEY_FILE"] = SOPS_AGE_KEY_FILE

    result = subprocess.run(
        [SOPS_PATH, "--decrypt", encrypted_file_path],
        capture_output=True,
        text=True,
        env=env
    )

    if result.returncode != 0:
        raise RuntimeError(f"SOPS decrypt failed: {result.stderr}")

    return yaml.safe_load(result.stdout)


def load_environment_config(environment):
    """Load config for a given environment (dev, staging)."""
    config_path = os.path.join("configs", environment, "config.enc.yaml")
    return decrypt_config(config_path)


def get_config_value(config, *keys):
    """Safely get a nested value from config dict. Example: get_config_value(config, 'database', 'host')"""
    current = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


if __name__ == "__main__":
    print("--- Loading Dev Config ---")
    dev_config = load_environment_config("dev")
    print(f"App: {get_config_value(dev_config, 'app', 'name')}")
    print(f"Environment: {get_config_value(dev_config, 'app', 'environment')}")
    print(f"DB Host: {get_config_value(dev_config, 'database', 'host')}")
    print(f"DB Password: {get_config_value(dev_config, 'database', 'password')}")

    print("\n--- Loading Staging Config ---")
    staging_config = load_environment_config("staging")
    print(f"App: {get_config_value(staging_config, 'app', 'name')}")
    print(f"Environment: {get_config_value(staging_config, 'app', 'environment')}")
    print(f"DB Host: {get_config_value(staging_config, 'database', 'host')}")
    print(f"DB Password: {get_config_value(staging_config, 'database', 'password')}")
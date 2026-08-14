"""
VaultGuard - Configuration Drift Detector

Compares HCL policy files in vault-policies/ (Git source of truth)
against policies currently loaded in Vault (live enforcement state).

Exits 0 if in sync, 1 if drift detected.
Suitable for use as a CI gate.
"""

import os
import sys
import glob
import hvac
from dotenv import load_dotenv

load_dotenv()

POLICY_DIR = "vault-policies"
IGNORE_POLICIES = {"default", "root", "default-ceiling"}


def normalise(text):
    """Normalise HCL text for comparison - strip whitespace and comments."""
    lines = []
    for line in text.splitlines():
        stripped = line.split("#")[0].strip()
        if stripped:
            lines.append(" ".join(stripped.split()))
    return "\n".join(lines)


def get_git_policies():
    """Load all HCL policies from disk (Git source of truth)."""
    policies = {}
    pattern = os.path.join(POLICY_DIR, "*.hcl")
    for filepath in glob.glob(pattern):
        name = os.path.basename(filepath).replace(".hcl", "")
        with open(filepath, "r") as f:
            policies[name] = f.read()
    return policies


def get_vault_policies(client):
    """Fetch all policies currently loaded in Vault."""
    policies = {}
    all_names = client.sys.list_policies()["data"]["policies"]
    for name in all_names:
        if name in IGNORE_POLICIES:
            continue
        result = client.sys.read_policy(name)
        policies[name] = result["data"]["rules"]
    return policies


def compare_policies(git_policies, vault_policies):
    """Return (matches, missing_in_vault, missing_in_git, content_mismatches)."""
    git_names = set(git_policies.keys())
    vault_names = set(vault_policies.keys())

    matches = []
    content_mismatches = []
    missing_in_vault = sorted(git_names - vault_names)
    missing_in_git = sorted(vault_names - git_names)

    for name in sorted(git_names & vault_names):
        git_norm = normalise(git_policies[name])
        vault_norm = normalise(vault_policies[name])
        if git_norm == vault_norm:
            matches.append(name)
        else:
            content_mismatches.append({
                "name": name,
                "git_lines": git_norm.count("\n") + 1,
                "vault_lines": vault_norm.count("\n") + 1
            })

    return matches, missing_in_vault, missing_in_git, content_mismatches


def print_report(matches, missing_in_vault, missing_in_git, content_mismatches):
    """Print a human-readable drift report."""
    print("=" * 60)
    print("VaultGuard - Configuration Drift Report")
    print("=" * 60)
    print()

    total_git = len(matches) + len(missing_in_vault) + len(content_mismatches)
    total_vault = len(matches) + len(missing_in_git) + len(content_mismatches)

    print("Git policies:   " + str(total_git))
    print("Vault policies: " + str(total_vault))
    print()

    if matches:
        print("[MATCH] " + str(len(matches)) + " policies in sync:")
        for name in matches:
            print("  - " + name)
        print()

    drift_detected = False

    if missing_in_vault:
        drift_detected = True
        print("[DRIFT] Policies in Git but NOT in Vault (" + str(len(missing_in_vault)) + "):")
        for name in missing_in_vault:
            print("  - " + name + "  (Vault not enforcing this policy)")
        print()

    if missing_in_git:
        drift_detected = True
        print("[DRIFT] Policies in Vault but NOT in Git (" + str(len(missing_in_git)) + "):")
        for name in missing_in_git:
            print("  - " + name + "  (untracked policy - possibly edited in UI)")
        print()

    if content_mismatches:
        drift_detected = True
        print("[DRIFT] Policies with content differences (" + str(len(content_mismatches)) + "):")
        for m in content_mismatches:
            print("  - " + m["name"] + "  (Git: " + str(m["git_lines"]) + " lines, Vault: " + str(m["vault_lines"]) + " lines)")
        print()

    print("=" * 60)
    if drift_detected:
        print("RESULT: DRIFT DETECTED - Vault does not match Git source of truth")
        print("REMEDIATION: Re-run 'python src/vault/setup_vault.py'")
    else:
        print("RESULT: IN SYNC - All policies match between Git and Vault")
    print("=" * 60)

    return drift_detected


def main():
    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.getenv("VAULT_TOKEN")

    if not vault_token:
        print("[ERROR] VAULT_TOKEN not set in environment")
        sys.exit(2)

    client = hvac.Client(url=vault_addr, token=vault_token)

    if not client.is_authenticated():
        print("[ERROR] Vault authentication failed")
        sys.exit(2)

    print("Loading policies from Git (" + POLICY_DIR + "/)...")
    git_policies = get_git_policies()
    print("  Found " + str(len(git_policies)) + " HCL files")

    print("Fetching live policies from Vault...")
    vault_policies = get_vault_policies(client)
    print("  Found " + str(len(vault_policies)) + " policies in Vault")
    print()

    matches, missing_in_vault, missing_in_git, content_mismatches = compare_policies(
        git_policies, vault_policies
    )

    drift = print_report(matches, missing_in_vault, missing_in_git, content_mismatches)

    sys.exit(1 if drift else 0)


if __name__ == "__main__":
    main()
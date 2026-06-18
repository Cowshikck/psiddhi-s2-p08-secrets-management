"""
VaultGuard - Anomaly Detector Unit Tests
Tests the rule-based detection functions (no API calls).
"""

import pytest
from src.ai.anomaly_detector import (
    detect_off_hours_access,
    detect_unusual_pairing,
    detect_abnormal_frequency,
    load_audit_logs,
    run_rule_based_detection
)


def make_entry(identity, policies, path, hour, display_name=None):
    """Helper to create a test audit log entry."""
    if display_name is None:
        display_name = identity
    return {
        "time": "2026-06-10T{:02d}:30:00+00:00".format(hour),
        "auth": {
            "display_name": display_name,
            "policies": policies,
            "token_type": "service",
            "client_token_accessor": "test_accessor"
        },
        "request": {
            "id": "req_test",
            "operation": "read",
            "path": path,
            "remote_address": "10.0.1.100"
        },
        "response": {"status_code": 200},
        "is_anomaly": False,
        "anomaly_type": None
    }


class TestOffHoursDetection:
    """Test off-hours access detection."""

    def test_detects_late_night_access(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/db-credentials/postgres-main", 3)]
        result = detect_off_hours_access(entries)
        assert len(result) == 1
        assert result[0]["anomaly_type"] == "off_hours_access"

    def test_ignores_business_hours(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/db-credentials/postgres-main", 14)]
        result = detect_off_hours_access(entries)
        assert len(result) == 0

    def test_ignores_cicd_off_hours(self):
        entries = [make_entry("github-actions-cicd", ["cicd"],
                              "secret/data/db-credentials/postgres-main", 3)]
        result = detect_off_hours_access(entries)
        assert len(result) == 0

    def test_detects_early_morning(self):
        entries = [make_entry("admin-bob", ["platform-admin"],
                              "secret/data/db-credentials/postgres-main", 2)]
        result = detect_off_hours_access(entries)
        assert len(result) == 1

    def test_detects_late_night_22(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/db-credentials/postgres-main", 23)]
        result = detect_off_hours_access(entries)
        assert len(result) == 1


class TestUnusualPairingDetection:
    """Test unusual identity-secret pairing detection."""

    def test_detects_developer_accessing_service_tokens(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/service-tokens/monitoring-agent", 10)]
        result = detect_unusual_pairing(entries)
        assert len(result) == 1
        assert result[0]["anomaly_type"] == "unusual_identity_secret_pairing"

    def test_developer_accessing_own_path_is_normal(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/db-credentials/postgres-main", 10)]
        result = detect_unusual_pairing(entries)
        assert len(result) == 0

    def test_developer_accessing_tls_certs_is_unusual(self):
        entries = [make_entry("dev-user-alice", ["developer"],
                              "secret/data/tls-certificates/web-frontend", 10)]
        result = detect_unusual_pairing(entries)
        assert len(result) == 1

    def test_cicd_not_flagged(self):
        entries = [make_entry("github-actions-cicd", ["cicd"],
                              "secret/data/service-tokens/monitoring-agent", 10)]
        result = detect_unusual_pairing(entries)
        assert len(result) == 0

    def test_admin_not_flagged(self):
        entries = [make_entry("admin-bob", ["platform-admin"],
                              "secret/data/tls-certificates/web-frontend", 10)]
        result = detect_unusual_pairing(entries)
        assert len(result) == 0


class TestAbnormalFrequencyDetection:
    """Test abnormal access frequency detection."""

    def test_detects_burst(self):
        entries = []
        for i in range(25):
            entries.append({
                "time": "2026-06-10T14:{:02d}:00+00:00".format(i % 5),
                "auth": {"display_name": "github-actions-cicd", "policies": ["cicd"],
                         "token_type": "service", "client_token_accessor": "test"},
                "request": {"id": "req_" + str(i), "operation": "read",
                            "path": "secret/data/db-credentials/postgres-main",
                            "remote_address": "10.0.1.1"},
                "response": {"status_code": 200},
                "is_anomaly": False, "anomaly_type": None
            })
        result = detect_abnormal_frequency(entries)
        assert len(result) >= 1
        assert result[0]["anomaly_type"] == "abnormal_access_frequency"

    def test_normal_frequency_not_flagged(self):
        entries = []
        for i in range(5):
            entries.append({
                "time": "2026-06-10T{:02d}:00:00+00:00".format(10 + i),
                "auth": {"display_name": "dev-user-alice", "policies": ["developer"],
                         "token_type": "service", "client_token_accessor": "test"},
                "request": {"id": "req_" + str(i), "operation": "read",
                            "path": "secret/data/db-credentials/postgres-main",
                            "remote_address": "10.0.1.1"},
                "response": {"status_code": 200},
                "is_anomaly": False, "anomaly_type": None
            })
        result = detect_abnormal_frequency(entries)
        assert len(result) == 0


class TestRuleBasedDetectionIntegration:
    """Test the full rule-based detection pipeline on real data."""

    def test_runs_on_synthetic_data(self):
        entries = load_audit_logs()
        result = run_rule_based_detection(entries)
        assert len(result) > 0

    def test_finds_all_three_types(self):
        entries = load_audit_logs()
        result = run_rule_based_detection(entries)
        types = set(a["anomaly_type"] for a in result)
        assert "off_hours_access" in types
        assert "unusual_identity_secret_pairing" in types
        assert "abnormal_access_frequency" in types
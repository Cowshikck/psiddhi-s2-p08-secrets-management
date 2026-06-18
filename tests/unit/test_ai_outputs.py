"""
VaultGuard - AI Output Validation Tests
Tests that AI-generated outputs meet quality rubrics.
"""

import pytest
import json
import os

POLICY_PATH = os.path.join("data", "rotation-policies.json")
ANOMALY_REPORT_PATH = os.path.join("data", "anomaly-report.json")
AUDIT_DOCS_PATH = os.path.join("data", "audit-documentation.json")


class TestRotationPolicies:
    """Validate AI-generated rotation policy quality."""

    @pytest.fixture(autouse=True)
    def load_policies(self):
        if not os.path.exists(POLICY_PATH):
            pytest.skip("rotation-policies.json not found")
        with open(POLICY_PATH, "r") as f:
            data = json.load(f)
        self.policies = data.get("policies", [])

    def test_four_categories_generated(self):
        assert len(self.policies) >= 4

    def test_each_policy_has_category(self):
        for p in self.policies:
            assert "category" in p

    def test_each_policy_has_interval(self):
        for p in self.policies:
            assert "recommended_rotation_interval_days" in p

    def test_intervals_are_reasonable(self):
        for p in self.policies:
            interval = p.get("recommended_rotation_interval_days")
            if interval is not None:
                assert 1 <= interval <= 365, (
                    p["category"] + " has unreasonable interval: " + str(interval)
                )

    def test_each_policy_has_strategy(self):
        for p in self.policies:
            assert "rotation_strategy" in p
            assert len(str(p["rotation_strategy"])) > 10

    def test_each_policy_has_justification(self):
        for p in self.policies:
            assert "justification" in p
            assert len(str(p["justification"])) > 10

    def test_critical_secrets_rotate_faster(self):
        """API keys and DB creds should rotate more frequently than service tokens."""
        intervals = {}
        for p in self.policies:
            cat = p.get("category", "")
            interval = p.get("recommended_rotation_interval_days")
            if interval is not None:
                intervals[cat] = interval

        if "api_keys" in intervals and "service_tokens" in intervals:
            assert intervals["api_keys"] <= intervals["service_tokens"]


class TestAnomalyReport:
    """Validate AI anomaly detection output quality."""

    @pytest.fixture(autouse=True)
    def load_report(self):
        if not os.path.exists(ANOMALY_REPORT_PATH):
            pytest.skip("anomaly-report.json not found")
        with open(ANOMALY_REPORT_PATH, "r") as f:
            self.report = json.load(f)

    def test_anomalies_detected(self):
        assert self.report.get("total_anomalies_detected", 0) > 0

    def test_three_anomaly_types(self):
        types = self.report.get("anomalies_by_type", {})
        assert len(types) >= 3

    def test_off_hours_detected(self):
        types = self.report.get("anomalies_by_type", {})
        assert "off_hours_access" in types

    def test_unusual_pairing_detected(self):
        types = self.report.get("anomalies_by_type", {})
        assert "unusual_identity_secret_pairing" in types

    def test_abnormal_frequency_detected(self):
        types = self.report.get("anomalies_by_type", {})
        assert "abnormal_access_frequency" in types

    def test_ai_narration_exists(self):
        narration = self.report.get("ai_narration", "")
        assert len(narration) > 100

    def test_narration_mentions_all_types(self):
        narration = self.report.get("ai_narration", "").lower()
        assert "off-hours" in narration or "off hours" in narration
        assert "unusual" in narration or "pairing" in narration
        assert "frequency" in narration or "burst" in narration


class TestAuditDocumentation:
    """Validate AI-generated audit documentation quality."""

    @pytest.fixture(autouse=True)
    def load_docs(self):
        if not os.path.exists(AUDIT_DOCS_PATH):
            pytest.skip("audit-documentation.json not found")
        with open(AUDIT_DOCS_PATH, "r") as f:
            self.docs = json.load(f)

    def test_three_themes_generated(self):
        assert len(self.docs) >= 3

    def test_access_policy_theme_exists(self):
        assert "access_policy_effectiveness" in self.docs

    def test_rotation_compliance_theme_exists(self):
        assert "rotation_compliance" in self.docs

    def test_anomaly_response_theme_exists(self):
        assert "anomaly_response" in self.docs

    def test_each_doc_has_content(self):
        for key, doc in self.docs.items():
            content = doc.get("content", "")
            assert len(content) > 200, key + " has too little content"

    def test_docs_mention_psiog(self):
        for key, doc in self.docs.items():
            content = doc.get("content", "").lower()
            assert "psiog" in content, key + " does not mention Psiog"


class TestAuditLogData:
    """Validate the synthetic audit log data quality."""

    @pytest.fixture(autouse=True)
    def load_logs(self):
        log_path = os.path.join("data", "synthetic", "vault-audit-logs.json")
        if not os.path.exists(log_path):
            pytest.skip("vault-audit-logs.json not found")
        with open(log_path, "r") as f:
            self.logs = json.load(f)

    def test_sufficient_entries(self):
        assert len(self.logs) >= 300

    def test_entries_have_required_fields(self):
        for entry in self.logs[:10]:
            assert "time" in entry
            assert "auth" in entry
            assert "request" in entry
            assert "response" in entry

    def test_multiple_identities_present(self):
        identities = set(e["auth"]["display_name"] for e in self.logs)
        assert len(identities) >= 3

    def test_anomalies_labeled(self):
        anomalies = [e for e in self.logs if e.get("is_anomaly")]
        assert len(anomalies) > 0

    def test_normal_entries_exist(self):
        normal = [e for e in self.logs if not e.get("is_anomaly")]
        assert len(normal) > len([e for e in self.logs if e.get("is_anomaly")])
# S2-P-08: Secrets Management and Rotation System

**VaultGuard** — End-to-end secrets management and rotation platform.

IMPACT pSiddhi 3.0 · Semester 2 · Platform Track · pSiddhi-2026-01

Cowshik Eswaramoorthy (P466)

## Overview

VaultGuard is a secrets management and rotation system built on HashiCorp Vault, integrated with Microsoft Entra ID for identity-based access control, automated through GitHub Actions, encrypted in Git via SOPS + age, and augmented by AI (Gemini + Groq) for rotation policy generation, anomaly detection, compliance mapping, and natural language audit querying.

## Key Metrics

| Metric | Value |
|--------|-------|
| Secret types managed | 5 (db-credentials, api-keys, service-tokens, tls-certificates, env-config) |
| Identity roles enforced | 3 (developer, cicd, platform-admin) via Entra ID OIDC |
| Automated rotations | 3 (db-credentials, api-keys, service-tokens) via GitHub Actions |
| SOPS-encrypted environments | 2 (dev, staging) |
| AI capabilities | 5 (anomaly detection, rotation policies, compliance docs, SOC 2/ISO 27001 mapping, NL audit query) |
| Dashboard tabs | 6 (Access Patterns, Rotation & Policies, Anomaly Feed, Compliance Docs, Ask Audit AI, Guidance) |
| Tests | 82 passing, 81% coverage |
| Load test | 7,524 requests, 0 failures, 3,817 req/min sustained, 10ms p95 |
| Budget spent | ₹0 of ₹2,500 |

## Architecture

```
Identities (Entra ID OIDC)
    → HashiCorp Vault (HCL policies, KV v2, audit device)
        → GitHub Actions (scheduled rotation workflows)
        → SOPS + age (encrypted env configs in Git)
        → AI Layer
            → Gemini 2.5 Flash (rotation policies, compliance docs, SOC 2/ISO 27001 mapping)
            → Groq Llama 3.3 70B (anomaly narration, NL audit query)
        → Streamlit Dashboard (6-tab visualisation)
```

## Tech Stack

| Layer | Technology | Cost |
|-------|-----------|------|
| Secrets Platform | HashiCorp Vault (Dev/OSS) — KV v2, audit device | Free |
| Identity | Microsoft Entra ID — OIDC auth | Free |
| Encrypted Secrets-in-Git | SOPS + age | Free |
| Automation | GitHub Actions — rotation workflows, CI/CD | Free |
| AI — Policy, Compliance, Mapping | Gemini 2.5 Flash (direct API) | Free |
| AI — Anomaly, NL Query | Groq Llama 3.3 70B | Free |
| Dashboard | Streamlit + Plotly | Free |
| Language | Python 3.13 + hvac + requests | Free |
| QA | Pytest + Locust + GitHub Actions CI | Free |

Note: LangChain was evaluated and deliberately not used. See `docs/decisions/langchain-decision.md` for the Architecture Decision Record.

## Quick Start

### Prerequisites

- Python 3.13+, pip
- HashiCorp Vault binary
- SOPS + age binaries
- Git

### 1. Start Vault (dev mode)

```bash
vault server -dev
# Copy the root token from output
```

### 2. Set environment variables

```bash
set VAULT_ADDR=http://127.0.0.1:8200
set VAULT_TOKEN=<root-token>
```

### 3. Update .env file

Copy the root token into `.env` as `VAULT_TOKEN`. Ensure `GEMINI_API_KEY` and `GROQ_API_KEY` are also set.

### 4. Seed Vault

```bash
python src/vault/setup_vault.py    # 5 secrets, 3 policies, audit device
python src/vault/setup_auth.py     # OIDC + userpass auth methods
```

### 5. Run the dashboard

```bash
streamlit run src/dashboard/app.py
# Opens at http://localhost:8501
```

### 6. Run tests

```bash
python -m pytest tests/ -v --cov=src
```

## Project Structure

```
psiddhi-s2-p08-secrets-management/
├── src/
│   ├── vault/
│   │   ├── setup_vault.py              # Seeds 5 secrets, loads 3 policies, enables audit
│   │   └── setup_auth.py              # Configures OIDC + userpass auth
│   ├── rotation/
│   │   ├── rotate_secrets.py          # Rotation logic for 3 secret types
│   │   └── dummy_consumer.py          # Simulates a service reading secrets
│   ├── sops/
│   │   └── config_loader.py           # SOPS decrypt + config loading
│   ├── ai/
│   │   ├── anomaly_detector.py        # Rule-based detection + Groq narration
│   │   ├── rotation_policy.py         # Gemini rotation policy generation
│   │   ├── audit_docs.py             # Gemini compliance documentation (3 themes)
│   │   ├── compliance_mapping.py      # SOC 2 / ISO 27001 mapping via Gemini
│   │   └── nl_audit_query.py         # Natural language audit querying via Groq
│   └── dashboard/
│       └── app.py                     # Streamlit dashboard (6 tabs)
├── vault-policies/
│   ├── developer.hcl                  # Read-only on db-credentials, api-keys
│   ├── cicd.hcl                       # Read on 4 secret paths
│   └── platform-admin.hcl            # Full CRUD on all paths + audit + policies
├── config/
│   ├── dev/config.enc.yaml            # SOPS-encrypted dev config
│   └── staging/config.enc.yaml        # SOPS-encrypted staging config
├── data/
│   ├── synthetic/vault-audit-logs.json # 409 synthetic audit entries
│   ├── anomaly-report.json            # Groq anomaly detection output
│   ├── rotation-log.json              # Rotation event history
│   ├── rotation-policies.json         # Gemini rotation policy recommendations
│   ├── audit-documentation.json       # Gemini compliance docs (3 themes)
│   └── compliance-mapping.json        # SOC 2 / ISO 27001 control mappings
├── docs/
│   ├── architecture.md
│   ├── access_policy_effectiveness.md
│   ├── rotation_compliance.md
│   ├── anomaly_response.md
│   ├── compliance_mapping.md          # SOC 2 / ISO 27001 mapping document
│   └── decisions/
│       └── langchain-decision.md      # ADR: LangChain deliberate non-use
├── tests/
│   └── unit/
│       ├── test_vault_policies.py     # 19 tests — allow/deny matrix
│       ├── test_sops.py               # 11 tests — encrypt/decrypt/tamper
│       ├── test_rotation.py           # 13 tests — version, consumer, stale check
│       ├── test_ai_outputs.py         # 25 tests — AI output structure validation
│       └── test_anomaly_detector.py   # 14 tests — rule-based detection
├── .github/workflows/
│   ├── ci-tests.yml                   # Pytest on every push/PR
│   ├── rotate-db-credentials.yml      # Monday 2am UTC
│   ├── rotate-api-keys.yml            # Wednesday 2am UTC
│   └── rotate-service-tokens.yml      # Friday 2am UTC
├── .coveragerc                        # Coverage config
├── .sops.yaml                         # SOPS config
├── .gitignore                         # Protects .env, key.txt, logs
├── requirements.txt
└── README.md
```

## AI Capabilities

### 1. Anomaly Detection (Groq)
Rule-based detection for 3 scenarios (off-hours access, unusual identity-secret pairing, frequency burst), with Groq Llama 3.3 70B generating plain-English narrations for security teams.

### 2. Rotation Policy Generation (Gemini)
Structured rotation policies for 4 secret categories with intervals, propagation strategies, and blast-radius notes grounded in audit data.

### 3. Compliance Documentation (Gemini)
AI-generated audit trail documentation covering 3 compliance themes: access policy effectiveness, rotation compliance, and anomaly response.

### 4. SOC 2 / ISO 27001 Compliance Mapping (Gemini)
Maps VaultGuard evidence to 6 specific controls (3 SOC 2 Trust Service Criteria + 3 ISO 27001 Annex A controls) with assessment and gap analysis.

### 5. Natural Language Audit Query (Groq)
Interactive querying over Vault audit logs in plain English. Ask questions like "Who accessed secrets after hours?" and get answers grounded in real audit data.

## QA Strategy

- **82 unit tests** across 5 test files, all passing
- **81% code coverage** (pytest-cov)
- **19 policy enforcement tests** — full 3-role × 5-path allow/deny matrix
- **13 rotation tests** — version increment, consumer verification, stale credential check
- **11 SOPS tests** — encrypt/decrypt roundtrip, tamper detection
- **25 AI output tests** — structure validation, content grounding
- **14 anomaly detection tests** — rule accuracy on crafted inputs
- **Load test** — 7,524 requests, 0 failures, 3,817 req/min sustained, 10ms p95, 20 concurrent users, 120 seconds
- **4 GitHub Actions workflows** — CI tests on every push + 3 scheduled rotation workflows

## Vault UI

Access the Vault web interface at `http://localhost:8200/ui` when Vault is running.

Login methods:
- **Token** — paste the root token for full access
- **OIDC** — Microsoft Entra ID login (browser redirect)
- **Userpass** — fallback with dev-user, cicd-service, admin-bob

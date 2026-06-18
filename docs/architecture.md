# VaultGuard — Architecture Document

**S2-P-08: Secrets Management and Rotation System**

IMPACT pSiddhi 3.0 · Semester 2 · Platform Track · Cowshik Eswaramoorthy (P466)

---

## System Overview

VaultGuard is an end-to-end secrets management and rotation platform that centralises secret storage, enforces identity-based access policies, automates secret rotation, encrypts secrets-in-Git, and uses AI for rotation policy generation, anomaly detection, and compliance documentation.

---

## Architecture Layers

### Layer 1: Centralised Secret Storage & Identity-Based Access

**Components:** HashiCorp Vault (Dev/OSS) + Userpass Auth (Entra ID fallback)

**How it works:**
- Vault runs as the centralised secrets store with KV v2 engine
- 5 secret types stored under structured paths: db-credentials, api-keys, service-tokens, tls-certificates, env-config
- 3 identity roles enforced via HCL policies: developer (read-only on db-creds and api-keys), cicd (read on dev + staging secrets), platform-admin (full CRUD)
- Userpass auth method maps users to policies (designed for Entra ID OIDC swap-in)
- Every secret access and write captured by Vault audit device to structured JSON logs

**Data flow:**
Identity (userpass login) → Vault (OIDC/userpass auth) → HCL Policy Check → Secret Read/Write → Audit Log

### Layer 2: Automated Rotation & Encrypted Secrets-in-Git

**Components:** Python rotation scripts + GitHub Actions + SOPS + age

**How it works:**
- 3 GitHub Actions workflows rotate db-credentials, api-keys, and service-tokens on schedule
- Rotation pattern: generate new credential → write to Vault (versioned) → verify consumer gets new value → verify no stale credentials → log rotation event
- SOPS + age encrypts environment config files (dev, staging) so they sit safely in Git
- python-dotenv + SOPS config loader provides decrypt-on-load for local development

**Data flow:**
GitHub Actions (cron/manual trigger) → Python rotation script → Vault write (new version) → Consumer verification → Rotation log

### Layer 3: AI Intelligence Layer

**Components:** Gemini 2.5 Flash + Groq (Llama 3.3 70B)

**How it works:**

**Rotation Policy Generation (Gemini):**
- For each of 4 secret categories, Gemini ingests category metadata (type, sensitivity, consumer count, usage pattern)
- Outputs structured JSON: recommended rotation interval, propagation strategy, blast-radius notes, pre/post-rotation checks
- Policies validated against reasonableness rubric (1-365 day intervals, critical secrets rotate faster)

**Anomaly Detection & Narration (Groq):**
- Rule-based pre-filtering flags 3 anomaly types from Vault audit logs: off-hours access, unusual identity-secret pairing, abnormal access frequency
- Flagged anomalies sent to Groq Llama 3.3 70B for plain-English security narration
- Each narration includes: what happened, risk assessment (severity), recommended action

**Audit Trail Documentation (Gemini):**
- Structured audit log summaries fed to Gemini covering 3 compliance themes: access policy effectiveness, rotation compliance, anomaly response
- Output: compliance-ready markdown documents with executive summary, findings, compliance status, recommendations

**Data flow:**
Vault Audit Logs → Rule-Based Detection → Groq Narration → Anomaly Report
Secret Category Metadata → Gemini → Rotation Policies
Audit Logs + Rotation Logs + Anomaly Report → Gemini → Compliance Documentation

### Layer 4: Dashboard & Visualisation

**Components:** Streamlit + Plotly

**Tabs:**
- Access Patterns: identity distribution, secret path usage, daily trends, hourly heatmap, status codes
- Rotation Status: rotation event log, per-secret rotation count, success rate, AI-generated rotation policies
- Anomaly Feed: anomaly type distribution, detailed anomaly list, Groq AI security narration
- Audit Summary: compliance documents for 3 review themes (expandable)

---

## Secret Types Managed

| # | Secret Type | Vault Path | Rotation | Sensitivity |
|---|-------------|------------|----------|-------------|
| 1 | Database Credentials | secret/data/db-credentials/ | Automated (GitHub Actions) | High |
| 2 | API Keys | secret/data/api-keys/ | Automated (GitHub Actions) | Critical |
| 3 | Service Tokens | secret/data/service-tokens/ | Automated (GitHub Actions) | Medium |
| 4 | TLS Certificates | secret/data/tls-certificates/ | Manual (PKI planned) | High |
| 5 | Environment Config | secret/data/env-config/ | Via SOPS re-encryption | Medium |

---

## Identity Roles & Access Matrix

| Secret Path | Developer | CI/CD | Platform Admin |
|-------------|-----------|-------|----------------|
| db-credentials | READ | READ | FULL |
| api-keys | READ | READ | FULL |
| service-tokens | DENY | READ | FULL |
| tls-certificates | DENY | DENY | FULL |
| env-config | DENY | READ | FULL |

---

## QA Coverage

| Test Suite | Tests | What It Covers |
|------------|-------|---------------|
| test_vault_policies.py | 19 | Allow/deny matrix for all 3 roles x 5 secret paths |
| test_rotation.py | 13 | Rotation logic, version increment, consumer propagation, stale credential check, log integrity |
| test_sops.py | 11 | Encrypt/decrypt roundtrip, tamper detection, config structure, file-not-found handling |
| test_ai_outputs.py | 25 | Rotation policy quality, anomaly report completeness, audit doc quality, synthetic data integrity |
| test_anomaly_detector.py | 14 | Off-hours detection, unusual pairing, burst frequency, rule-based pipeline integration |
| **TOTAL** | **82** | **81% code coverage** |

---

## Tech Stack

| Layer | Technology | Cost |
|-------|-----------|------|
| Secrets Platform | HashiCorp Vault (Dev/OSS) | Free |
| Identity | Userpass (Entra ID OIDC fallback) | Free |
| Encrypted Secrets-in-Git | SOPS + age | Free |
| Automation | GitHub Actions | Free |
| AI - Policy & Docs | Gemini 2.5 Flash | Free |
| AI - Anomaly Analysis | Groq (Llama 3.3 70B) | Free |
| Dashboard | Streamlit + Plotly | Free |
| Language | Python 3.13 | Free |
| QA | Pytest + GitHub Actions CI | Free |

**Total cost: Rs.0 (all free tiers and open-source)**

---

## File Structure
psiddhi-s2-p08-secrets-management/

├── src/

│   ├── vault/          # Vault setup, policies, auth

│   ├── rotation/       # Rotation logic, dummy consumers

│   ├── sops/           # SOPS config loader

│   ├── ai/             # Gemini + Groq AI pipelines

│   ├── dashboard/      # Streamlit app

│   └── utils/          # Shared helpers

├── tests/

│   └── unit/           # 82 tests, 81% coverage

├── .github/workflows/  # 3 rotation + 1 CI workflow

├── configs/            # SOPS-encrypted dev + staging configs

├── vault-policies/     # HCL policy files

├── docs/               # Architecture + compliance docs

├── data/               # Audit logs, rotation logs, AI outputs

└── .env.example        # Environment template
---

## Entra ID Integration Note

The current implementation uses Vault's userpass auth method as a documented fallback due to IT access restrictions on the Psiog Entra ID tenant (Error 401 — insufficient privileges). The architecture is designed for a direct swap: when Application Developer role access is granted, the userpass auth method is replaced with OIDC auth pointing to the Entra ID tenant. All HCL policies remain identical — only the auth method changes.

---

*VaultGuard — S2-P-08 · Cowshik Eswaramoorthy (P466) · pSiddhi-2026-01*
# S2-P-08: Secrets Management and Rotation System

**VaultGuard** — End-to-end secrets management and rotation platform.

IMPACT pSiddhi 3.0 · Semester 2 · Platform Track · pSiddhi-2026-01

## Overview

A secrets management and rotation system built on HashiCorp Vault, integrated with Microsoft Entra ID for identity-based access control, automated through GitHub Actions, encrypted in Git via SOPS, and augmented by AI (Gemini + Groq) for rotation policy generation, anomaly detection, and audit documentation.

## Tech Stack

- **Secrets Platform:** HashiCorp Vault (Dev/OSS)
- **Identity:** Microsoft Entra ID (OIDC)
- **Automation:** GitHub Actions
- **Encrypted Secrets-in-Git:** SOPS + age
- **AI - Policy & Docs:** Gemini 2.5 Flash + LangChain
- **AI - Anomaly Analysis:** Groq (Llama 3.3 70B)
- **Dashboard:** Streamlit + Plotly
-
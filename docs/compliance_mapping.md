# VaultGuard - SOC 2 / ISO 27001 Compliance Mapping

Generated: 2026-08-11T10:17:28.041306+00:00

This document maps VaultGuard's secrets management controls to specific SOC 2 Trust Service Criteria and ISO 27001 Annex A controls.

---

## SOC2-CC6.1 - CC6.1 - Logical Access Security

**Framework:** SOC 2

**Requirement:** The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.

Compliance Mapping Document

1. Control Objective:
This control requires the entity to implement and maintain logical access security mechanisms for protected information assets to prevent unauthorized access and security incidents. This includes defining and enforcing access policies, authenticating users, and monitoring access attempts.

2. Evidence Provided:
- VaultGuard utilizes HashiCorp Vault with KV v2 engine for secret management.
- Access is enforced via HCL policies for 3 distinct identity roles: developer, cicd, and platform-admin.
- Authentication is managed through Microsoft Entra ID OIDC.
- Specific access policies are defined:
    - developer: read-only on db-credentials and api-keys paths.
    - cicd: read on db-credentials, api-keys, service-tokens, env-config paths.
    - platform-admin: full CRUD on all secret paths, plus audit and policy read.
- There are 19 automated policy enforcement tests (allow/deny matrix) to validate policy effectiveness.
- The audit log summary shows 409 total events, with 403 successful (200) and 6 denied (403) requests. The 6 denied requests align with policy enforcement.
- Identity distribution shows distinct users/systems interacting with VaultGuard: github-actions-cicd (188 events), dev-user-alice (113 events), admin-bob (108 events).
- The system has 82 automated tests with 81% code coverage, indicating a robust testing approach for the system itself.

3. Assessment:
Satisfied.
The evidence demonstrates that VaultGuard has implemented logical access security controls that meet the requirements of CC6.1. Distinct roles (developer, cicd, platform-admin) with granular HCL policies are enforced, restricting access to specific secret paths (e.g., developer read-only on db-credentials and api-keys). Authentication is handled by Microsoft Entra ID OIDC, a robust identity provider. The presence of 19 automated policy enforcement tests and the audit log showing 6 denied requests (403) confirm that policies are actively enforced and effective in preventing unauthorized access attempts. The clear distribution of identities interacting with the system further supports the implementation of logical access controls.

4. Gaps and Recommendations:
No significant gaps were identified based on the provided evidence. The control is well-implemented.

Recommendations for hardening:
- Implement regular reviews of HCL policies and role assignments to ensure they remain aligned with the principle of least privilege as organizational roles and secret types evolve.
- Establish alerts for repeated denied access attempts or unusual access patterns in the audit logs to proactively identify potential security incidents or misconfigurations.
- Consider implementing multi-factor authentication (MFA) for all human users accessing VaultGuard, if not already enforced by Microsoft Entra ID, to add an additional layer of security.

---

## SOC2-CC6.7 - CC6.7 - Restriction of Data at Rest

**Framework:** SOC 2

**Requirement:** The entity restricts the transmission, movement, and removal of information to authorised internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives.

Compliance Mapping Document

1. Control Objective:
The entity restricts the transmission, movement, and removal of information to authorised internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives. This control primarily focuses on the protection of data at rest and during movement.

2. Evidence Provided:
- Vault KV v2 engine encrypts secrets at rest in its storage backend.
- SOPS + age asymmetric encryption is used for 2 environment configs (dev, staging) stored in Git.
- The private key for SOPS + age encryption is stored outside the repository and gitignored.
- 11 automated SOPS tests include tamper detection.
- HMAC hashing of sensitive values is performed in audit logs.
- 3 identity roles (developer, cicd, platform-admin) are enforced via HCL policies, restricting access to secrets.
- Microsoft Entra ID OIDC authentication is used for identity.
- Audit logs show 6 denied (403) events out of 409 total events, indicating access control enforcement.

3. Assessment: Satisfied
The control is Satisfied. VaultGuard demonstrates robust mechanisms for protecting data at rest and restricting its movement. The use of Vault KV v2's inherent encryption for secrets and SOPS + age encryption for environment configurations directly addresses the requirement for data at rest protection. The private key for SOPS being stored outside the repo and gitignored further strengthens this. The enforcement of 3 distinct identity roles via HCL policies and the presence of 6 denied access events in the audit logs indicate effective restriction of access and movement to authorized users and processes. HMAC hashing of sensitive values in audit logs also contributes to protecting information during its movement within the logging system.

4. Gaps and Recommendations:
No significant gaps were identified based on the provided evidence.

Recommendations for hardening measures:
- Implement automated scanning for unencrypted secrets or configuration files within repositories to ensure consistent application of SOPS + age encryption.
- Periodically review and update HCL policies for the 3 identity roles to ensure least privilege is maintained as system requirements evolve.
- Conduct regular penetration testing specifically targeting the encryption mechanisms and access controls to identify potential vulnerabilities.
- Ensure a robust key rotation strategy is in place for both Vault's encryption keys and the SOPS + age private keys.

---

## SOC2-CC7.2 - CC7.2 - Monitoring of System Components

**Framework:** SOC 2

**Requirement:** The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.

Compliance Mapping Document

1. Control Objective:
The entity monitors system components and their operations to detect anomalies indicative of malicious acts, natural disasters, or errors that could impact the entity's objectives. This includes continuous observation for unusual or unauthorized activities within the system.

2. Evidence Provided:
- Vault audit device logs every read, write, and authentication event as structured JSON.
- Audit logging is synchronous, meaning a failed log write results in the request being denied, ensuring log integrity.
- AI anomaly detection is implemented with 3 defined scenarios: off-hours access, unusual identity-secret pairing, and abnormal access frequency.
- A total of 12 anomalies have been detected, categorized as 'off_hours_access', 'unusual_identity_secret_pairing', and 'abnormal_access_frequency'.
- Groq AI narrates each detected anomaly in plain English for the security team.
- There are 14 automated anomaly detection tests in place.
- The system processes 409 total audit events, with 403 successful and 6 denied.

3. Assessment:
Satisfied.
VaultGuard demonstrates robust monitoring capabilities directly addressing the CC7.2 control. The synchronous audit logging ensures comprehensive capture of all events, with a fail-safe mechanism for log integrity. The implementation of AI-driven anomaly detection across three distinct scenarios, coupled with automated anomaly detection tests, provides proactive identification of potentially malicious or unusual activities. The narration of anomalies by Groq AI facilitates timely understanding and response by the security team. The detection of 12 anomalies and their categorization further demonstrates the active and effective operation of the monitoring system.

4. Gaps and Recommendations:
No significant gaps were identified based on the provided evidence. The control is fully satisfied.

Recommendations for hardening measures in production:
- Implement automated alerting and incident response workflows for detected anomalies to ensure prompt investigation and mitigation beyond just narration.
- Regularly review and update the AI anomaly detection scenarios and models to adapt to evolving threat landscapes and system usage patterns.
- Establish clear metrics and reporting for the effectiveness of anomaly detection, including false positive rates and time-to-detection for known threats.
- Consider integrating VaultGuard's monitoring data with a broader Security Information and Event Management (SIEM) system for centralized correlation with other security telemetry.

---

## ISO27001-A9.2.3 - A.9.2.3 - Management of Privileged Access Rights

**Framework:** ISO 27001

**Requirement:** The allocation and use of privileged access rights shall be restricted and controlled.

Compliance Mapping Document

1. Control Objective:
This control requires that the allocation and use of privileged access rights within the secrets management system are restricted and controlled to prevent unauthorized access and misuse.

2. Evidence Provided:
-   Three distinct identity roles (developer, cicd, platform-admin) are enforced via HCL policies, demonstrating a structured approach to access allocation.
-   Specific path restrictions are defined for each role:
    -   'developer' role has read-only access on 'db-credentials' and 'api-keys' paths.
    -   'cicd' role has read access on 'db-credentials', 'api-keys', 'service-tokens', and 'env-config' paths.
    -   'platform-admin' role has full CRUD on all secret paths, plus audit and policy read capabilities, indicating a highly privileged role.
-   Access policies are subject to 19 automated policy enforcement tests (allow/deny matrix), providing assurance of policy correctness.
-   The audit log summary shows 6 denied (403) requests out of 409 total events, indicating that access controls are actively enforcing restrictions.
-   Microsoft Entra ID OIDC authentication is used, suggesting external identity management and potentially centralized control over user identities.
-   The system has 82 automated tests with 81% code coverage, which contributes to the reliability and integrity of the access control mechanisms.

3. Assessment: Satisfied
The control is Satisfied. The evidence clearly demonstrates that privileged access rights are restricted and controlled. The use of distinct roles with granular, path-specific HCL policies, coupled with automated policy enforcement tests and active denial of unauthorized requests in the audit logs, directly addresses the requirement for restricted and controlled allocation and use of privileged access. The integration with Microsoft Entra ID OIDC further supports controlled identity management.

4. Gaps and Recommendations:
No significant gaps are identified based on the provided evidence. The control appears to be well-implemented.

Recommendations for hardening measures in production:
-   Implement a regular review process for all HCL policies, especially for the 'platform-admin' role, to ensure they remain appropriate and adhere to the principle of least privilege as system requirements evolve.
-   Establish alerts for repeated denied access attempts (403s) to identify potential malicious activity or misconfigured applications/users.
-   Consider implementing multi-factor authentication (MFA) enforcement for all human users accessing VaultGuard, particularly for 'platform-admin' accounts, even if Entra ID handles it.
-   Periodically review the 'Identity distribution' to ensure that the number of users or service accounts assigned to highly privileged roles (e.g., 'platform-admin') is minimized and justified.
-   Ensure that the automated rotation via GitHub Actions for 3 secret types is regularly audited to confirm successful rotations and prevent stale secrets, which indirectly reduces the window of opportunity for misuse of privileged secrets.

---

## ISO27001-A9.2.4 - A.9.2.4 - Management of Secret Authentication Information

**Framework:** ISO 27001

**Requirement:** The allocation of secret authentication information shall be controlled through a formal management process including regular rotation.

Control Objective:
This control requires that the allocation of secret authentication information is managed through a formal process, including regular rotation, to ensure its security and integrity.

Evidence Provided:
- HashiCorp Vault with KV v2 engine manages 5 secret types.
- 3 identity roles (developer, cicd, platform-admin) are enforced via HCL policies.
- Automated rotation is implemented for 3 secret types (db-credentials, api-keys, service-tokens) via GitHub Actions.
- Rotation schedules are Mon/Wed/Fri at 2am UTC.
- Each rotation process includes generating new values, writing to Vault, verifying version increments, confirming consumer access to new values, and verifying old value staleness.
- 13 automated rotation tests are in place.
- 54 recent rotation events have occurred.
- Microsoft Entra ID OIDC authentication is used.
- 82 automated tests with 81% code coverage are present.
- Audit logs show 403 successful events and 6 denied events out of 409 total.

Assessment:
Partially Satisfied.
The system demonstrates a formal management process for secret allocation through defined roles and policies, and a robust automated rotation mechanism for a subset of secrets. Evidence includes the use of HCL policies for 3 identity roles, automated rotation for 3 secret types with specific schedules and verification steps, and 13 automated rotation tests. However, automated rotation is only confirmed for 3 out of 5 secret types managed by VaultGuard, indicating that not all secret authentication information is subject to regular rotation as required by the control.

Gaps and Recommendations:
Gaps:
- Automated rotation is not confirmed for all 5 secret types managed by VaultGuard. Two secret types are not explicitly covered by the automated rotation process.
- The "AI-recommended intervals" for rotation are unknown, suggesting a lack of data-driven optimization or formal review of rotation frequency.

Recommendations:
- Implement automated rotation for the remaining 2 secret types managed by VaultGuard to ensure all secret authentication information is regularly rotated.
- Establish and document formal rotation intervals for all secret types, considering risk, impact, and operational requirements. If AI recommendations are available, integrate them into the formal process.
- Expand automated rotation tests to cover all secret types once rotation is implemented for them.
- Document the formal management process for secret allocation, including roles, responsibilities, and the complete lifecycle of secrets, to further demonstrate adherence to the "formal management process" aspect of the control.

---

## ISO27001-A12.4.1 - A.12.4.1 - Event Logging

**Framework:** ISO 27001

**Requirement:** Event logs recording user activities, exceptions, faults, and information security events shall be produced, kept, and regularly reviewed.

Compliance Mapping Document

1. Control Objective:
This control requires the generation, retention, and regular review of event logs for user activities, exceptions, faults, and information security events within the system.

2. Evidence Provided:
- VaultGuard's audit device logs every read, write, and authentication event as structured JSON.
- Audit logging is synchronous, meaning a failed log write results in a denied request, ensuring log integrity.
- The system recorded a total of 409 events, comprising 403 successful (200) and 6 denied (403) events.
- AI anomaly detection is implemented with 3 scenarios (off-hours, unusual pairing, frequency burst), detecting a total of 12 anomalies.
- Anomaly types detected include 'off_hours_access', 'unusual_identity_secret_pairing', and 'abnormal_access_frequency'.
- Groq AI narrates each anomaly in plain English for the security team.
- There are 14 automated anomaly detection tests.

3. Assessment: Satisfied
The control is satisfied. VaultGuard comprehensively logs all relevant events (read, write, auth) in a structured format, and the synchronous logging mechanism ensures log completeness and integrity. The presence of AI-driven anomaly detection, with specific scenarios and plain English narration, demonstrates a proactive approach to reviewing these logs for security events. The recorded successful and denied events confirm the logging mechanism is active and capturing system activity.

4. Gaps and Recommendations:
No gaps were identified based on the provided evidence for the core requirements of A.12.4.1.

Recommendations for hardening in production:
- While anomaly detection is present, the evidence does not explicitly state the frequency or process for regular review of the audit logs by human operators. It is recommended to establish and document a formal process for periodic human review of the audit logs and anomaly alerts, including defined roles and responsibilities.
- The retention period for audit logs was not specified. It is recommended to define and enforce a log retention policy that aligns with organizational and regulatory requirements.
- Consider implementing automated alerts for specific critical denied events (e.g., repeated failed authentication attempts from a single source) beyond the existing anomaly detection.

---


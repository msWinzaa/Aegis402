# Aegis402 — Production Security & India Compliance Readiness

## Scope

This document describes engineering controls implemented in this release and the controls that still require deployment, independent assessment, or regulated-entity decisions. It is **not legal advice, a regulatory approval, or a claim of PCI/RBI/DPDP compliance**.

## Decision architecture

Aegis uses a deterministic security core before probabilistic AI:

1. hard payment/context/freshness/replay/policy checks;
2. deterministic risk features;
3. optional AI risk probability as bounded evidence;
4. deterministic risk-policy thresholds;
5. x402 verification/settlement;
6. independent settlement verification when required;
7. immutable audit evidence.

AI never receives unilateral authorization authority. An AI score is treated as probabilistic evidence unless independently proven/validated; its influence is bounded by `ai_risk_weight` and deterministic policy thresholds.

## India regulatory baseline considered

- **Digital Personal Data Protection Act, 2023 (DPDP Act)**: applies when Aegis processes digital personal data in scope. The Act establishes obligations around lawful processing and individual data rights. The 2025 Rules were notified on 13 November 2025 with a phased commencement schedule. Deployment must map Aegis data flows, notices, purposes, retention, security safeguards, processor/controller roles and data-principal rights to the applicable commencement dates.
- **CERT-In Directions under section 70B**: applicable entities must maintain ICT logs securely for the prescribed rolling period and maintain a CERT-In point of contact; incident reporting and cooperation requirements apply according to the Directions and applicable FAQs.
- **RBI requirements**: whether a particular RBI direction applies depends on the legal role of the operating entity (bank, NBFC, payment system operator, payment aggregator, regulated entity, outsourced technology provider, etc.). This release therefore implements general security controls but does not assert that Aegis itself is an RBI-regulated entity. A regulated deployment requires a legal applicability matrix and contractual responsibility allocation.
- **PCI DSS**: PCI DSS applies where cardholder data / a cardholder-data environment is in scope. Aegis should be designed to avoid unnecessary card data handling. Where it does impact a cardholder-data environment, PCI DSS v4.0.1 and the applicable validation path must be assessed by the responsible entity/QSA.

## Production blockers that code cannot close alone

1. Regulatory classification and licensing analysis by Indian counsel/compliance.
2. Data-fiduciary/processor role allocation and DPDP notices/consents/legitimate-purpose analysis as applicable.
3. CERT-In incident-response contact and operational procedures.
4. RBI applicability determination and regulated-entity approval/outsourcing arrangements where applicable.
5. PCI DSS scope determination and formal assessment where applicable.
6. Real KMS/HSM deployment and key ceremonies.
7. Real RPC/facilitator/chain infrastructure and operational contracts.
8. Independent penetration test, cryptographic review and security audit.
9. Production disaster-recovery exercises and evidence.
10. Human governance for policy changes, risk thresholds and model changes.

## Stage-8 evidence target

A production release should retain evidence for:

- unit/integration/property/fuzz/security tests;
- dependency/SBOM/SAST/DAST results;
- threat-model review;
- key-management and access-control review;
- incident-response exercises;
- disaster-recovery RTO/RPO tests;
- settlement-verification test vectors per supported mechanism;
- AI model validation, calibration, drift and adversarial testing;
- independent audit findings and remediation.

## Important capability states

Aegis must expose explicit states rather than silently simulating production capabilities:

- EVM anchoring: configured/unavailable
- independent settlement verification: configured/degraded/unavailable
- x402 facilitator: configured/unavailable
- AI risk provider: configured/unavailable
- HSM: hardware-backed/software
- administrator authentication: required/not required

Production policy should fail closed or hold when a required security dependency is unavailable.

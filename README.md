# Ciphermind Audit Platform



## Overview
Ciphermind is a cryptography governance and readiness analysis tool that scans
code repositories for classical and post-quantum cryptographic usage, detects
misuse patterns, and produces auditable security reports.

The core engine is fully deterministic and rule-based. Optional AI components
may be used for advisory explanations and report summarization, but never for
authoritative detection or scoring.

Ciphermind does not perform cryptographic correctness proofs, side-channel analysis, or vulnerability exploitation. It focuses on governance, readiness, and misuse detection. AI output is informational only and is never used to determine security posture, compliance status, or pass/fail outcomes.

## Modules
- Deterministic Cryptography Scanner
- PQC Readiness & Migration Analysis
- Crypto Misuse Detection (Rule-based)
- CI/CD & DevSecOps Integration
- Optional AI Advisory Layer (Non-authoritative)


## Quickstart
```bash
git clone https://github.com/sumitgiri87/ciphermind-audit.git
cd ciphermind-audit
# run scanner example
```
## Reports
- PQC Readiness Score
- Crypto Hygiene Reports

## Documentation
See the `ciphermind/docs/` directory for architecture, API, and research notes.


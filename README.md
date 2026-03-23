# CipherMind PQC Audit Tool

A post-quantum cryptography (PQC) audit tool that scans a codebase,
detects cryptographic algorithm usage, assesses quantum readiness,
and generates actionable migration recommendations.

Given any Python repository, the tool answers:

- **What crypto is used?** — parsed from a Cryptographic Bill of Materials (CBOM)
- **Is it PQC-ready?** — evaluated against a YAML rule engine
- **What should be migrated, and to what?** — structured AI guidance via Ollama

---

## Architecture

```
repo → CodeQL → SARIF → cryptobom-forge → cbom.json
                                              │
                                    ┌─────────▼──────────┐
                                    │  cbom/parser.py     │  parse
                                    │  cbom/normalizer.py │  canonicalize
                                    └─────────┬──────────┘
                                              │ CryptoAsset[]
                                    ┌─────────▼──────────┐
                                    │  rule_engine.py     │  flag weak crypto
                                    └─────────┬──────────┘
                                              │ RuleFinding[]
                                    ┌─────────▼──────────┐
                                    │  ai_recommender.py  │  migration guidance
                                    └─────────┬──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  output_writer.py   │  final_report.json
                                    └────────────────────┘  summary.md
```

The pipeline splits cleanly at the CBOM boundary:
- **cryptobom-forge** (black box): converts CodeQL SARIF → CBOM JSON
- **Our code starts at the parser**: normalize → classify → recommend → report

---

## Installation

```bash
# 1. Clone and enter the project
git clone https://github.com/your-handle/ciphermind-audit
cd ciphermind-audit

# 2. Install with dev dependencies
pip install -e ".[dev]"

# 3. Install Ollama (for AI recommendations)
# macOS/Linux: https://ollama.ai
ollama pull llama3
```

> **Note:** CodeQL CLI and cryptobom-forge are required only for the `audit scan`
> command (the full pipeline). The `audit analyze` command works standalone
> with any existing `cbom.json`.

---

## Quick Start

### Analyze an existing CBOM (no CodeQL required)

```bash
audit analyze tests/fixtures/sample_cbom.json --no-ai
```

### Analyze with AI recommendations (requires Ollama running)

```bash
ollama serve &
audit analyze tests/fixtures/sample_cbom.json
```

### Full scan (requires CodeQL + cryptobom-forge)

```bash
audit scan /path/to/your/python-repo
```

### View a prior audit

```bash
audit report my-python-app
```

---

## Output

Reports are written to `audits/<project-name>/reports/`:

```
audits/my-python-app/
└── reports/
    ├── final_report.json   ← machine-readable, all findings + AI recs
    └── summary.md          ← human-readable markdown summary
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — no findings |
| `1`  | High severity findings detected |
| `2`  | Critical findings detected |

This makes `audit analyze` composable in CI pipelines:

```yaml
# .github/workflows/crypto-audit.yml
- run: audit analyze cbom/cbom.json --no-ai
  # Step fails on critical findings
```

---

## PQC Rules (`configs/pqc_rules.yml`)

| Rule ID  | Algorithm       | Severity | Reason |
|----------|----------------|----------|--------|
| RULE-001 | MD5            | Critical | Collision attacks trivially possible |
| RULE-002 | SHA-1          | High     | SHAttered collision attack (2017) |
| RULE-003 | RSA < 2048-bit | Critical | Factored by modern hardware |
| RULE-004 | RSA (any)      | High     | Vulnerable to Shor's algorithm |
| RULE-005 | ECDSA          | High     | Vulnerable to Shor's algorithm |
| RULE-006 | AES-ECB        | Critical | Deterministic — leaks data patterns |
| RULE-007 | 3DES           | High     | Sweet32 attack, NIST deprecated 2017 |
| RULE-008 | RC4            | Critical | Broken stream cipher, RFC 7465 banned |
| RULE-009 | ECDH           | High     | Vulnerable to Shor's algorithm |
| RULE-010 | RSA-PKCS1v15   | Medium   | Bleichenbacher oracle attack |
| RULE-011 | RSA 2048–3072  | Medium   | Below NIST 2030 recommendation |
| RULE-012 | DSA            | High     | Deprecated, nonce reuse risk |

### NIST PQC Migration Targets

| Weak Algorithm | PQC Replacement |
|---------------|-----------------|
| RSA (key exchange) | **ML-KEM** (FIPS 203, formerly Kyber) |
| RSA/ECDSA (signatures) | **ML-DSA** (FIPS 204, formerly Dilithium) |
| ECDSA (signatures) | **FN-DSA** (FIPS 206, formerly Falcon) |
| ECDH (key agreement) | **ML-KEM** |
| SHA-1 / MD5 | **SHA-3-256** or **SHAKE256** |

---

## Development

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov

# Run a specific test module
pytest tests/test_rule_engine.py -v

# Verify the CLI
audit analyze tests/fixtures/sample_cbom.json --no-ai
```

### Project Structure

```
pqc-audit-tool/
├── cbom/               # CBOM parsing and normalization
│   ├── models.py       # CryptoAsset dataclass
│   ├── parser.py       # cbom.json → CryptoAsset[]
│   └── normalizer.py   # canonicalize variant/primitive strings
├── recommender/
│   ├── rule_engine.py  # YAML rule evaluation → RuleFinding[]
│   └── ai_recommender.py # Ollama LLM layer → AIRecommendation[]
├── cli/
│   └── main.py         # Typer CLI: scan / analyze / report
├── scanner/
│   └── codeql_runner.py # CodeQL subprocess wrapper
├── utils/
│   ├── output_writer.py # Writes final_report.json + summary.md
│   └── logging_config.py
├── configs/
│   └── pqc_rules.yml   # PQC policy rules
├── tests/
│   ├── fixtures/
│   │   └── sample_cbom.json
│   ├── test_cbom_parser.py
│   ├── test_rule_engine.py
│   ├── test_ai_recommender.py
│   ├── test_cli.py
│   └── test_output_writer.py
└── audits/             # per-project output (gitignored)
```

---

## Design Principles

- **Local-first** — no cloud dependency; Ollama runs locally
- **Modular** — each component independently runnable and testable
- **AI for recommendations only** — never for crypto operations
- **Fail loudly** — if Ollama is down without `--no-ai`, the tool errors with a fix hint
- **CI-composable** — exit codes make it drop-in for GitHub Actions

---

## License

MIT

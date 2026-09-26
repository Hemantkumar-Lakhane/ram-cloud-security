# RAM Cloud Security — Developer & Setup Guide

## 1. Local Environment Setup

### 1.1 Prerequisites
- Python 3.10+ (Python 3.11 or 3.12 recommended)
- Git
- AWS CLI v2 (optional for offline testing, required for live telemetry ingestion)

### 1.2 Virtual Environment & Installation
```bash
# 1. Clone repository
git clone https://github.com/Hemantkumar-Lakhane/portfolio.git ram-cloud-security
cd ram-cloud-security

# 2. Create Python virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (cmd.exe):
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. Environment Configuration

1. Copy the template configuration:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` to match your local setup.
3. **CRITICAL SECURITY RULE:**
   - **Never** commit `.env` or hardcode AWS secret keys in any source file.
   - Use standard AWS credential providers: `~/.aws/credentials`, IAM instance profiles, or environment variables in local sessions only.

---

## 3. Directory Layout & Module Structure

```
ram-cloud-security/
├── src/
│   ├── ingestion/       # Telemetry ingestion sources (CloudTrail, etc.)
│   ├── preprocessing/   # Event parsing and OCSF schema normalization
│   ├── features/        # Statistical and behavioral feature extraction
│   ├── detection/
│   │   ├── rules/       # Deterministic rule engine modules
│   │   └── ml/          # ML anomaly detection models and trainers
│   ├── risk/            # Risk scoring and contextual prioritization
│   ├── response/        # Safe/dry-run response orchestration
│   └── common/          # Shared domain models, configurations, loggers
├── data/                # Data lake partitions (raw, processed, features)
├── experiments/         # ML experiments and validation scripts
├── tests/               # Pytest unit and integration test suite
└── scripts/             # Operational utility scripts
```

---

## 4. Running Tests & Code Quality

Run the test suite with `pytest`:
```bash
# Run all tests
pytest -v

# Run with test coverage
pytest --cov=src -v
```

---

## 5. Development Workflow & Principles

1. **Principle of Least Privilege:** When testing against live AWS accounts, use read-only IAM policies (e.g. `SecurityAudit` or `AWSCloudTrail_ReadOnlyAccess`).
2. **Deterministic vs. Probabilistic:** Use rules for deterministic policy/misconfiguration checks; use ML only for behavioral anomaly detection.
3. **Safe Response Operations:** All automated response actions in `src/response/` MUST default to `DRY_RUN = True` and require explicit human confirmation flags.
4. **Clean Code & Type Annotations:** Use Python type hints (`from typing import ...`) and Pydantic models for data interchange.

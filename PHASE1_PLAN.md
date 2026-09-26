# RAM Cloud Security — Phase 1 Implementation Plan

## 1. Goal & Scope
Build a robust, offline-capable, schema-validated AWS CloudTrail telemetry ingestion and normalization layer. This constitutes the raw data foundation before applying any feature engineering, detection rules, or ML anomaly models.

---

## 2. Implementation Steps

### Step 1: Synthetic & Fixture Datasets (`tests/fixtures/cloudtrail/`)
Create realistic, safe synthetic CloudTrail JSON and JSONL fixtures with zero committed credentials:
- `normal_event.json`: Standard IAM/S3 management event (`DescribeInstances`, `GetCallerIdentity`).
- `unusual_login.json`: `ConsoleLogin` event with anomalous user agent and source IP.
- `privilege_escalation.json`: `AttachUserPolicy` with `AdministratorAccess` or wildcard grants.
- `sensitive_access.json`: `GetObject` on sensitive S3 bucket with access denial / permission details.
- `sample_events.jsonl`: Multi-event JSONL file for streaming ingestion tests.

### Step 2: Concrete CloudTrail Ingestion Engine (`src/ingestion/cloudtrail.py`)
Implement `CloudTrailIngestion(BaseTelemetryIngestion)`:
- Supports local single JSON file (`.json`).
- Supports CloudTrail envelope format (`{"Records": [...]}`).
- Supports line-delimited JSON (`.jsonl`).
- Supports gzip-compressed archives (`.json.gz`, `.jsonl.gz`).
- Supports read-only AWS S3 collection via `boto3` client with paginated `get_object` (with mock-friendly interfaces).
- Offline-first: operates seamlessly without AWS credentials when ingesting local files.

### Step 3: Normalization Layer (`src/preprocessing/parser.py`)
Implement `CloudTrailParser(BaseEventParser)`:
- Maps raw CloudTrail JSON payloads into the standardized `NormalizedEvent` model (`src/common/models.py`).
- Fields extracted & normalized:
  - Timestamp (converted to UTC ISO 8601 `datetime`).
  - Event name (`eventName`), event source (`eventSource`), region (`awsRegion`), account ID.
  - Identity context: `actor_arn`, `actor_name`, `actor_type`, `session_issuer_arn`.
  - Network & client context: `source_ip`, `user_agent`.
  - Status & error context: `status_code`, `error_code`, `error_message`.
  - Resource identifiers (`resources` array).
  - Safe raw payload preservation without credential leakage.

### Step 4: Comprehensive Unit & Integration Tests (`tests/test_ingestion_cloudtrail.py`, `tests/test_preprocessing.py`)
- Test valid single-event JSON and multi-record envelope parsing.
- Test missing optional fields (graceful degradation, default None).
- Test malformed JSON handling (exception raising or error logging).
- Test JSONL streaming and gzip-compressed file ingestion.
- Test timestamp parsing (ISO 8601 UTC variations).
- Test mock S3 collection without real AWS network calls.
- 100% offline executable.

---

## 3. Definition of Done (DoD) for Phase 1
- [x] Synthetic fixtures created in `tests/fixtures/cloudtrail/`.
- [x] `CloudTrailIngestion` implemented and tested across JSON, JSONL, and gzip.
- [x] Read-only S3 collector implemented with mock tests.
- [x] Raw CloudTrail events normalize deterministically into `NormalizedEvent`.
- [x] Unit tests cover edge cases (missing fields, malformed data, multi-event envelopes).
- [x] Zero real credentials or secrets committed.
- [x] All unit tests pass cleanly offline.
- [x] Documentation synchronized and completion notes recorded.

# RAM Cloud Security — Backend API Specification (REST Contract)

## 1. Overview & Authentication
- **Base URL:** `/api/v1`
- **Authentication:** Bearer token / API Key (Read-only endpoints public in local development mode; mutating endpoints require explicit authorization tokens).
- **Format:** `application/json`

---

## 2. Endpoint Specifications

### 2.1 System & Data Lake
- **`GET /api/v1/health`**
  - *Purpose:* Checks application, data lake, and engine status.
  - *Response:* `{"status": "healthy", "environment": "development", "data_lake": "accessible"}`
- **`GET /api/v1/datasets/stratus/summary`**
  - *Purpose:* Retrieves dataset dimensions, time range, 4-tier activity counts, and service breakdown.
  - *Response:* Summary object matching `experiments/results/eda_summary.json`.

---

### 2.2 Telemetry & Normalization
- **`GET /api/v1/events`**
  - *Parameters:* `limit` (default 50), `offset`, `actor_name`, `service`, `is_error`, `start_time`, `end_time`.
  - *Response:* Paginated list of `NormalizedEvent` objects.
- **`GET /api/v1/events/{event_id}`**
  - *Response:* Single `NormalizedEvent` with sanitized raw payload.

---

### 2.3 Security Findings & Detections
- **`GET /api/v1/findings`**
  - *Parameters:* `detection_type` (`RULE`, `ML_ANOMALY`, `HYBRID`), `severity`, `rule_id`, `status`.
  - *Response:* List of `SecurityFinding` objects with evidence and MITRE ATT&CK references.
- **`GET /api/v1/identities/{actor_name}/timeline`**
  - *Response:* Chronological sequence of API actions, anomaly scores, and triggered rules for a specific principal.

---

### 2.4 Research Experiments & Benchmarks
- **`GET /api/v1/experiments`**
  - *Response:* List of completed and planned experimental baselines.
- **`GET /api/v1/experiments/baseline-a`**
  - *Response:* Baseline A (Rules Only) metrics: precision, recall, F1, confusion matrix, technique coverage.

---

### 2.5 Safe Response Orchestration (Policy-Gated)
- **`POST /api/v1/response/preview`**
  - *Input:* `{"finding_id": "...", "action_type": "QUARANTINE_PRINCIPAL"}`
  - *Behavior:* Performs **dry-run simulation**; zero mutating AWS API calls.
  - *Response:* `{"dry_run": true, "simulated_action": "DetachUserPolicy", "affected_resource": "...", "status": "SIMULATED"}`
- **`POST /api/v1/response/approve`**
  - *Input:* `{"action_id": "...", "approval_token": "...", "operator_id": "analyst-1"}`
  - *Behavior:* Requires explicit human confirmation; logs audit record in `ResponseActionRecord`.

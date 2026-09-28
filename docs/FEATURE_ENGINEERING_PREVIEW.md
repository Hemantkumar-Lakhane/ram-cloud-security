# Feature Engineering Preview (Conceptual Specification — No Implementation Code)

## 1. Objective & Anti-Leakage Constraints

This document outlines the planned feature extraction logic for Phase 3. **No implementation code is included in this phase.**

### Anti-Leakage Mandate:
- **Prohibited:** Raw `userAgent` string tokens, `stratus-red-team` substrings, detonation UUIDs, tool names.
- **Allowed:** Only behavioral metrics, temporal rates, error frequencies, transition probabilities, and categorical entity types.

---

## 2. Planned Feature Catalog

| Category | Candidate Feature | Source Fields | Transformation Logic | Security Signal |
|---|---|---|---|---|
| **Temporal Velocity** | `events_last_1m` | `timestamp` | Rolling count of events in 60s window per actor. | High-frequency API bursts (automation/enumeration). |
| | `events_last_5m` | `timestamp` | Rolling count of events in 300s window per actor. | Extended operational velocity. |
| | `inter_arrival_mean_5m` | `timestamp` | Mean time (seconds) between consecutive calls. | Automated script execution vs human typing cadence. |
| | `inter_arrival_std_5m` | `timestamp` | Standard deviation of inter-arrival times. | Velocity regularity indicator. |
| **Error Dynamics** | `error_count_5m` | `error_code` | Count of errored API calls in 5m window. | Access failure frequency. |
| | `error_rate_5m` | `error_code` | `error_count_5m / events_last_5m`. | Ratio of failed authorization attempts (permission probing). |
| | `is_throttled_flag` | `error_code` | Binary flag for `ThrottlingException`. | API rate-limit exhaustion from rapid automation. |
| **Kill-Chain API Ratios** | `discovery_ratio_5m` | `event_name` | Fraction of calls starting with `Describe*`, `List*`, `Get*`. | Reconnaissance and environment mapping. |
| | `credential_api_count_5m`| `event_name` | Count of calls to `GetPasswordData`, `GetSecretValue`, `GetParameter`, `Decrypt`. | Sensitive credential access. |
| | `privilege_change_count_5m`| `event_name` | Count of IAM policy, user, or role mutation calls. | Privilege escalation and backdoor creation. |
| | `defense_evasion_count_5m`| `event_name` | Count of calls modifying trails, flow logs, or bucket policies. | Audit disruption and logging evasion. |
| **Cross-Service Dispersion**| `distinct_services_5m` | `event_source` | Number of distinct AWS services accessed in 5m window. | Lateral movement and broad resource enumeration. |
| **Identity Context** | `actor_type_encoded` | `actor_type` | One-hot encoding (`IAMUser`, `AssumedRole`, `AWSService`). | Principal authorization boundary. |
| | `client_category_encoded`| `user_agent` | Generic parsing (`AWS-CLI`, `SDK-Go`, `SDK-Java`, `Console`, `Internal`) without tool tokens. | Client environment baseline. |

---

## 3. Data Transformations & Output Specification
- **Scaling:** `StandardScaler` for continuous velocity features; `MinMaxScaler` for ratio features bounded in $[0, 1]$.
- **Output Artifact:** Persisted as `data/features/stratus_cloudtrail_features.parquet` containing event IDs, timestamp indexes, and numeric feature columns ($2,900 \times 16$).

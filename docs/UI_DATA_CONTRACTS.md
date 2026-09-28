# RAM Cloud Security — UI Data Contracts & Provenance Traceability

This document establishes the exact data binding contracts connecting UI views to active repository files, backend engines, and planned future modules.

---

## 1. Complete Screen Data Binding Matrix

| Screen Route | UI Component / Widget | Backend / Data Source | Availability Status | Fallback / State When Unavailable |
| :--- | :--- | :--- | :--- | :--- |
| `/security/overview` | Stat Strip (Total Events, Findings) | `experiments/results/rule_baseline_metrics.json`, `eda_summary.json` | **Active / Available** | N/A (Precomputed or stream generated) |
| `/security/overview` | Fig 09 Event Velocity Density | `reports/figures/eda/09_event_timeline.png` | **Active / Available** | Empty graph outline |
| `/security/overview` | Fig 01 Activity Tier Breakdown | `reports/figures/eda/01_dataset_activity_distribution.png` | **Active / Available** | Empty graph outline |
| `/security/findings` | Findings Data Table | `RuleEngine.evaluate_event()` stream over parsed CloudTrail | **Active / Available** | "No findings match active filters" |
| `/security/findings/:id`| Rule Evidence Accordion | `SecurityFinding.evidence` dictionary | **Active / Available** | Key-value list |
| `/security/findings/:id`| ML Anomaly Evidence Accordion | *Phase 4 ML Inference Engine* | **Not Evaluated** | State Banner: *"Phase 4 ML Anomaly Model not evaluated"* |
| `/security/findings/:id`| Temporal Sequence Accordion | *Phase 5 Temporal Graph / GNN* | **Not Evaluated** | State Banner: *"Phase 5 Graph Sequence not evaluated"* |
| `/security/investigation`| Tactic Swimlane (Fig 14) | `reports/figures/eda/14_attack_sequence_timeline.png` | **Active / Available** | Empty timeline view |
| `/security/investigation`| Service Heatmap (Fig 12) | `reports/figures/eda/12_service_activity_heatmap.png` | **Active / Available** | Empty heatmap grid |
| `/environment/assets` | Cloud Assets Inventory Table | Unique resource ARNs in `NormalizedEvent.resource_id` | **Active / Available** | "No discovered cloud assets" |
| `/environment/identities`| Identity Inventory Table | Sanitized actor mapping in `generate_eda_figures.py` | **Active / Available** | Table with 14 sanitized actors |
| `/environment/identities/:id`| Identity Profile Matrix (Fig 13)| `reports/figures/eda/13_identity_service_relationship.png` | **Active / Available** | Single-panel fallback |
| `/environment/workloads`| Container Runtime Pods | *Phase 7 eBPF Workload Daemon* | **Coming Soon** | State Banner: *"Workload monitoring planned for Phase 7"* |
| `/posture/misconfigurations`| Misconfiguration Findings Table| Findings from `RULE-CFG-001` through `RULE-CFG-004` | **Active / Available** | List of 36 configuration alerts |
| `/posture/vulnerabilities`| Vulnerability CVE Table | *AWS Inspector / Trivy Ingestion* | **Not Connected** | State Banner: *"Vulnerability ingestion connector not configured"* |
| `/detection/events` | Telemetry Event Explorer | `CloudTrailIngestion` + `CloudTrailParser` | **Active / Available** | Virtualized 2,900-row table |
| `/detection/threats` | Detonation Run Inventory | 83 Detonation UUIDs from label audit | **Active / Available** | Table of 83 runs (17 detected / 66 missed) |
| `/research/dataset` | Dataset Card & Provenance Table | `docs/DATASET_CARD.md`, `docs/DATASET_LABEL_AUDIT.md` | **Active / Available** | Rendered markdown & summary table |
| `/research/eda` | 14 Research Figures Gallery | `reports/figures/eda/01_*.png` through `14_*.png` | **Active / Available** | 14 high-DPI figure cards with full metadata |
| `/research/experiments`| Benchmark Comparison Matrix | `experiments/results/rule_baseline_metrics.json` | **Active / Available** | Table with Baseline A metrics + Phase 4/6 slots |
| `/response/center` | Response Recommendation Queue | `src/response/` policy engine recommendations | **Active (Simulated)** | Dry Run action preview modal |
| `/response/history` | Response Action Audit Table | Local immutable response log file | **Active (Simulated)** | Table of executed dry-run actions |

---

## 2. Dynamic Metric Calculation Contracts

To ensure complete scientific integrity, no frontend UI component may display hard-coded summary values. All metrics must parse dynamically from the following JSON contracts:

### 2.1 EDA Summary Contract (`experiments/results/eda_summary.json`)
- `total_records`: Integer (2,900)
- `four_tier_breakdown`: Object containing counts and percentages for `pure_detonation`, `stratus_warmup_cleanup`, `operator_terraform`, and `aws_background_internal`.
- `distinct_counts`: Object containing distinct counts for `services`, `event_names`, `actors`, `source_ips`.
- `error_metrics`: Object containing `total_errors` (300), `error_rate_pct` (10.34%), and `top_error_codes`.

### 2.2 Baseline A Evaluation Contract (`experiments/results/rule_baseline_metrics.json`)
- `total_events`: Integer (2,900)
- `total_findings`: Integer (42)
- `definition_1_stratus_associated`: `{tp: 23, fp: 19, precision: 0.5476, recall: 0.0201, f1: 0.0387}`
- `definition_2_pure_detonations`: `{tp: 13, fp: 29, precision: 0.3095, recall: 0.0607, f1: 0.1016}`
- `definition_3_technique_runs`: `{total_runs: 83, detected_runs: 17, technique_recall: 0.2048}`

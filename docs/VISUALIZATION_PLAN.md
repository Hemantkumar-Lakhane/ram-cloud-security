# RAM Cloud Security — Visualization Plan & Artifact Mapping

## 1. Mapping Matrix: Visual Artifacts to UI & Reports

| Figure ID & Filename | Graph Type | Data Source | Primary UI Location | Primary Document Location |
|---|---|---|---|---|
| `01_dataset_activity_distribution.png` | Bar Chart | `tier` column | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.1) |
| `02_service_distribution.png` | Horizontal Bar Chart | `event_source` | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.2) |
| `03_api_distribution.png` | Horizontal Bar Chart | `event_name` | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.3) |
| `04_pure_detonation_api_distribution.png` | Horizontal Bar Chart | `tier == 'Pure Detonation'` | Investigation Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.4) |
| `05_attack_technique_distribution.png` | Bar Chart | MITRE tactic mapping | Investigation Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.5) |
| `06_identity_distribution.png` | Horizontal Bar Chart | `actor_name` | Overview & EDA Pages | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.6) |
| `07_success_error_distribution.png` | Pie Chart | `is_error` | Overview & EDA Pages | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.7) |
| `08_error_type_distribution.png` | Horizontal Bar Chart | `error_code` | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.8) |
| `09_event_timeline.png` | Line / Area Density | Resampled 1-min counts | Overview & EDA Pages | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.9) |
| `10_activity_timeline.png` | Stacked Area Chart | 2-min binned tiers | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.10) |
| `11_stratus_terraform_overlap.png` | Horizontal Bar Chart | User-Agent overlap logic | EDA Explorer Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.11) |
| `12_service_activity_heatmap.png` | Heatmap | 5-min service counts | Investigation Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.12) |
| `13_identity_service_relationship.png` | Interaction Matrix | Actor $\times$ Service crosstab | Investigation Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.13) |
| `14_attack_sequence_timeline.png` | Scatter / Trace Plot | Pure detonation sequence | Investigation Page | [`docs/EDA_REPORT.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/EDA_REPORT.md) (§2.14) |

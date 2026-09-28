# RAM Cloud Security — Future Module UX & Placeholder Strategy

This document establishes the design protocol for representing future research modules, unintegrated telemetry sources, and unmodeled machine learning stages without fabricating functionality or confusing reviewers.

---

## 1. The Honesty-First Principle

In an academic and industry research product, presenting non-existent capabilities as working creates immediate credibility loss. RAM Cloud Security enforces three core principles:
1. **Never render fake progress bars or random simulated percentages** (e.g., no "ML Accuracy: 97.4%").
2. **Every future capability must have a transparent architectural status** (Phase target, required input schema, theoretical model architecture).
3. **Interactive controls for future modules must be disabled** with clear tooltips explaining the prerequisite phase requirements.

---

## 2. Standardized Future State Archetypes

```
+-----------------------------------------------------------------------------------+
| 1. NOT EVALUATED (Applicable to Phase 4 / 5 / 6 Machine Learning & Fusion)          |
| Visual: Slate/Neutral container with dashed border and Phase Roadmap Chip.        |
| Text: "ML Model Inference has not been evaluated on this telemetry record."        |
| Subtext: "Scheduled for implementation in Phase 4 (Anomaly Detection Engine)."   |
+-----------------------------------------------------------------------------------+
| 2. NOT CONNECTED (Applicable to External Telemetry Connectors)                    |
| Visual: Amber muted container with plug-off icon and configuration link.          |
| Text: "Telemetry connector is not configured."                                    |
| Action: [View Ingestion Specification]                                            |
+-----------------------------------------------------------------------------------+
| 3. COMING SOON (Applicable to Long-Term Posture & Workload Capabilities)         |
| Visual: Indigo subtle badge with architectural schematic preview.                 |
| Text: "Workload eBPF runtime agent targeted for Phase 7."                         |
+-----------------------------------------------------------------------------------+
```

---

## 3. Future Module Implementation Matrix

| Module / Feature Area | Target Project Phase | Current UI Representation | Required Prerequisite Before Live |
| :--- | :--- | :--- | :--- |
| **ML Feature Engineering** | Phase 3 | Read-only schema preview ([`docs/FEATURE_ENGINEERING_PREVIEW.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/FEATURE_ENGINEERING_PREVIEW.md)) | Feature vector pipeline & normalizer |
| **ML Anomaly Detection** | Phase 4 | Experiment benchmark slot tagged `[Phase 4 Target]` | Isolation Forest / Autoencoder training |
| **Temporal Graph & GNN** | Phase 5 | Attack sequence view tagged `[Phase 5 Graph Engine]` | Graph construction pipeline & PyG / DGL |
| **Multi-Source Fusion** | Phase 6 | Forensic evidence accordion tagged `[Phase 6 Fusion]` | Confidence calibration engine & Dempster-Shafer/Bayesian layer |
| **Workload eBPF Agent** | Phase 7 | Workload screen rendered with architectural schematic | Linux kernel probe daemon |
| **Live AWS Remediation** | Production Phase | Response Center locked to `DRY_RUN = True` | Production AWS IAM role with KMS permissions |
| **AWS Inspector Ingestion**| Integration Phase| Vulnerability tab rendered with `Not Connected` state | S3 / EventBridge bridge to Inspector v2 |
| **VPC Flow Logs Engine** | Integration Phase| Network tab rendered with `Not Connected` state | Athena / Parquet log query connector |

---

## 4. Reusable Empty & Future State UI Patterns

### 4.1 Benchmark Comparison Table Pattern (`/research/experiments`)
When displaying the benchmark table, unimplemented models occupy structured rows with clear status markers:

```markdown
| Detection Paradigm | Status | Precision | Recall | F1-Score | Latency | Artifact Link |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Baseline A (Rules Only)** | **Active / Evaluated** | **54.76%** | **2.01%** | **0.0387** | **6.0s** | [`rule_baseline_metrics.json`](file:///c:/Users/lakha/ml_ram_antivirous/experiments/results/rule_baseline_metrics.json) |
| **Baseline B (ML Anomaly)** | *Phase 4 (Not Evaluated)* | — | — | — | — | `docs/EXPERIMENT_PLAN.md` |
| **Baseline C (Temporal Graph)**| *Phase 5 (Not Evaluated)* | — | — | — | — | `docs/EXPERIMENT_PLAN.md` |
| **Proposed Hybrid Fusion** | *Phase 6 (Not Evaluated)* | — | — | — | — | `docs/RESEARCH_QUESTION.md` |
```

### 4.2 Forensic Detail Evidence Source Pattern (`/security/findings/:id`)
Inside the finding detail drawer, evidence tabs maintain clear capability boundaries:
- `[x] Rule Evidence (Triggered by RULE-CFG-001 on StopLogging)` $\to$ **Expanded by default**.
- `[ ] Identity Baseline Evidence` $\to$ **Collapsed / Available** (Historical service distribution).
- `[ ] ML Anomaly Score` $\to$ **Disabled Badge:** `Phase 4: Not Evaluated`.
- `[ ] Temporal Sequence Graph` $\to$ **Disabled Badge:** `Phase 5: Not Evaluated`.

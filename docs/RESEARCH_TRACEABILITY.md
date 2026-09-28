# RAM Cloud Security — Research Traceability Matrix

## 1. Traceability Architecture

Every numerical metric, table, figure, and claim in this project maps directly back to a deterministic calculation on the raw dataset:

```
Raw CloudTrail Data (data/raw/stratus_cloudtrail/CloudTrail/ - 55 JSON files)
       │
       ▼
Parsing & Normalization (src/preprocessing/parser.py -> NormalizedEvent)
       │
       ▼
Reproducible Experiment Scripts:
├── experiments/eda_cloudtrail.py          -> experiments/results/eda_summary.json
├── experiments/audit_dataset_labels.py    -> experiments/results/dataset_label_audit.json
└── experiments/evaluate_rule_baseline.py -> experiments/results/rule_baseline_metrics.json
       │
       ▼
Generated Visual Artifacts (reports/figures/eda/*.png - 14 PNG Figures)
       │
       ▼
Research Documentation (docs/*.md)
       │
       ▼
Backend REST API Contracts & Frontend UI Specifications
```

---

## 2. Key Metrics Traceability Table

| Metric / Result | Value | Source Raw Field / Logic | Calculating Script | Output Artifact |
|---|---|---|---|---|
| **Total Events** | 2,900 | Total parsed records from 55 files | `experiments/eda_cloudtrail.py` | `experiments/results/eda_summary.json` |
| **Pure Detonations** | 214 (7.38%) | `has_stratus and not has_tf` | `experiments/audit_dataset_labels.py` | `experiments/results/dataset_label_audit.json` |
| **Stratus Warmup/Cleanup** | 932 (32.14%) | `has_stratus and has_tf` | `experiments/audit_dataset_labels.py` | `experiments/results/dataset_label_audit.json` |
| **Operator Terraform** | 1,006 (34.69%)| `not has_stratus and has_tf` | `experiments/audit_dataset_labels.py` | `experiments/results/dataset_label_audit.json` |
| **AWS Background** | 748 (25.79%) | `not has_stratus and not has_tf`| `experiments/audit_dataset_labels.py` | `experiments/results/dataset_label_audit.json` |
| **Baseline A Findings** | 42 | Triggered rules across stream | `experiments/evaluate_rule_baseline.py` | `experiments/results/rule_baseline_metrics.json` |
| **Baseline A Precision** | 54.76% (Def 1) / 30.95% (Def 2) | $\text{TP} / (\text{TP} + \text{FP})$ | `experiments/audit_dataset_labels.py` | `docs/DATASET_LABEL_AUDIT.md` |
| **Baseline A Recall** | 2.01% (Def 1) / 6.07% (Def 2) | $\text{TP} / \text{Total Positives}$ | `experiments/audit_dataset_labels.py` | `docs/DATASET_LABEL_AUDIT.md` |
| **Technique Recall** | 20.48% (17 / 83 runs)| Runs with $\ge 1$ alert | `experiments/audit_dataset_labels.py` | `docs/DATASET_LABEL_AUDIT.md` |
| **Time to First Alert** | 6.0 seconds | $t_{\text{first\_alert}} - t_{\text{attack\_start}}$ | `experiments/evaluate_rule_baseline.py` | `experiments/results/rule_baseline_metrics.json` |

# RAM Cloud Security — Demonstration & Walkthrough Plan

## 1. Objective of the Demo

To demonstrate to evaluators and stakeholders:
1. Grounded empirical research on real AWS CloudTrail telemetry.
2. The fundamental limitation of static rules (Baseline A).
3. The power of multi-stage behavioral and temporal evidence fusion in catching zero-day and stealthy attack chains.
4. Robust, safe, policy-gated response automation.

---

## 2. Step-by-Step Walkthrough Flow

```
1. Dataset Provenance & 4-Tier Breakdown
   └── Show docs/DATASET_CARD.md and 01_dataset_activity_distribution.png
       Explain why 1,146 Stratus-associated events split into 214 detonations + 932 warmup/cleanup.

2. Exploratory Data Analysis (EDA) Insights
   └── Walk through reports/figures/eda/ (Service Heatmap, Error Profile, Attack Trace).
       Highlight the high burst density and cross-service dispersion during detonations.

3. Baseline A (Rules Only) Demonstration & Evaluation
   └── Show src/detection/rules/ evaluating normalized events.
       Show Baseline A results: Precision 54.76%, Recall 2.01%, 1,123 attack events missed.
       Explain WHY rules missed 97.99% of attacks (discovery & valid-credential access).

4. Behavioral Feature Engineering (Phase 3 Walkthrough)
   └── Explain sliding window velocity, error rate entropy, and kill-chain transition features.
       Highlight strict anti-leakage guarantees (zero userAgent tokens).

5. Baseline B (ML Anomaly) & Proposed Hybrid Fusion
   └── Compare ML anomaly scoring against static rules.
       Show multi-stage attack detection timeline (05_attack_technique_distribution.png).

6. Safe Policy-Gated Response
   └── Demonstrate DRY_RUN=True containment simulation and required human authorization gate.
```

# RAM Cloud Security — Research Gap Analysis

## 1. Existing Industry Solutions

| Solution / Platform | Capabilities & Focus | Remaining Limitations |
|---|---|---|
| **AWS Native (CloudTrail, GuardDuty, Security Hub, Inspector, Config)** | Comprehensive native telemetry, signature/ML threat detection, findings aggregation, cross-service correlation guides. | Findings are often siloed; correlation relies largely on static heuristics or pre-defined rule chains; behavioral models are proprietary black boxes with limited cross-source explainability. |
| **Commercial CNAPP / CSPM / CIEM (Microsoft Defender, Palo Alto Prisma, Wiz)** | Cloud security graph modeling, toxic combination analysis, attack-path visualization. | Emphasizes static configuration and topology risks; dynamic behavioral fusion from high-throughput event streams often remains decoupled from posture graphs. |
| **Enterprise SIEM / SOAR / XDR (Splunk, RAM Antivirus Suite, Sentinel)** | Ingests multi-source logs, applies correlation rules and UEBA scoring, executes automated playbooks. | High configuration overhead; alert fatigue from uncalibrated statistical thresholds; difficulty in evaluating true confidence and causal threat progression without manual tuning. |

---

## 2. Existing Academic Approaches

1. **CloudTrail Anomaly Detection via GNNs & Deep Learning:**
   - *What they solve:* Unsupervised representation learning on CloudTrail API logs to detect unusual API calls and reduce alert volume over static thresholds.
   - *Limitation in literature:* Evaluations frequently analyze only flagged events without measuring true false-negative rates; lack grounding in vulnerability and configuration state.
2. **Dynamic Cloud Graphs & Temporal Modeling:**
   - *What they solve:* Tracking evolving relationships between users, roles, sessions, and AWS API calls over time.
   - *Limitation in literature:* Scalability and graph explosion; often tested on synthetic or limited testbeds without multi-source signal fusion.
3. **Active Behavioral Validation for False-Positive Reduction:**
   - *What they solve:* Verifying whether a posture finding (e.g., exposed S3 bucket or open port) is genuinely reachable and exploitable given IAM boundaries.
   - *Limitation in literature:* Operates reactively on static posture scans; does not dynamically fuse live streaming behavioral anomaly evidence into the assessment.
4. **ML-Based Alert Prioritization:**
   - *What they solve:* Applying classifiers (Random Forest, Gradient Boosting) to prioritize vulnerability and posture alerts.
   - *Limitation in literature:* Often treats alerts as independent samples without tracking multi-stage attack progression or temporal causal links across identities.

---

## 3. Candidate Research Gaps

The literature reviewed to date indicates:
- **Gap 1 (Heterogeneous Evidence Fusion):** Existing approaches predominantly treat behavioral anomaly detection (UEBA on CloudTrail) and posture evaluation (IAM/Config/Inspector) as separate pipelines. A standardized, confidence-calibrated framework fusing these disparate evidence types remains insufficiently validated.
- **Gap 2 (Progression vs. Point Anomaly Detection):** While point anomaly detection on CloudTrail is mature, determining the calibrated mathematical confidence that a sequence of low-severity, temporally dispersed events constitutes an advancing attack chain is underexplored.
- **Gap 3 (Explainability & Calibration in Cloud Security):** Existing ML models produce raw anomaly scores that lack calibrated probabilistic meaning and transparent signal attribution across multi-stage incidents.

---

## 4. Novelty Risks & Guardrails

- **Risk:** Claiming "graph correlation" or "temporal correlation" as inherently novel when AWS documentation and recent IEEE publications already utilize dynamic graphs and cross-service correlation.
- **Guardrail:** Any claim of contribution must be anchored in rigorous comparative benchmarking against baseline models (Rules-only, ML-only, Rules+ML heuristic) under standardized experimental metrics (Precision, Recall, F1, PR-AUC, Latency, Calibration Error).

---

## 5. Evidence Required Before Claiming Novelty

Before any final academic or industrial novelty claim is formulated:
1. **Literature Matrix Completion:** Systematic mapping of 16+ recent papers (2024–2026) detailing Problem, Dataset, Method, Evaluation, and Unresolved Limitations.
2. **Reproducible Baseline Experiments:** Quantitative comparison proving the proposed evidence-fusion method outperforms standard UEBA and rule baselines on realistic datasets (e.g. DataDog Grimoire).
3. **Ablation Studies:** Proving that each component (identity context, temporal reasoning, confidence calibration) provides statistically significant improvements to detection or false-positive reduction.

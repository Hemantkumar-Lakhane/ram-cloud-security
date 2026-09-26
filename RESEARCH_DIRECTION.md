# RAM Cloud Security — Research Direction & Problem Framing

## 1. Problem Framing

The broad cloud security problem (workload monitoring, IAM analysis, misconfiguration scanning, threat detection, and alert management) is already commercially mature and addressed by production systems across multiple categories:
- **Cloud Security Posture Management (CSPM):** e.g., AWS Config, Prisma Cloud.
- **Cloud Infrastructure Entitlement Management (CIEM):** e.g., Ermetic/Tenable, CyberArk.
- **Cloud Workload Protection Platforms (CWPP):** e.g., Microsoft Defender for Cloud, CrowdStrike Falcon.
- **SIEM / SOAR / XDR:** e.g., RAM Antivirus security suite, Splunk, AWS Security Hub.

Consequently, simply implementing a cloud security dashboard or generic telemetry monitoring is not an academic or research innovation.

---

## 2. Research Motivation

The narrower, unaddressed challenge in cloud security operations is **multi-source evidence fusion for multi-stage threat progression under high alert volume and operational uncertainty**.

In an enterprise AWS environment:
- An attacker compromises an IAM credential, performs privilege escalation, interacts with a vulnerable EC2 workload, and executes data staging/exfiltration.
- Individual events viewed in isolation often appear benign or produce low-confidence alerts that cause alert fatigue.
- Point scanners (Inspector, Config) lack behavioral awareness, while anomaly detectors (CloudTrail UEBA) lack asset and vulnerability context.

The research objective is to investigate:
- **Heterogeneous Evidence Fusion:** Unifying telemetry from API audits (CloudTrail), IAM configurations, runtime state, and vulnerability scanners.
- **Contextual Reasoning:** Incorporating identity privilege, asset criticality, and resource relationships.
- **Temporal Context:** Determining whether sequential events within sliding time windows constitute a single evolving threat progression.
- **Calibrated, Explainable Confidence:** Producing reliable probabilistic risk scores with transparent evidence attribution rather than uncalibrated black-box anomaly flags.
- **Safe Policy-Gated Response:** Establishing response mechanisms with strict dry-run guarantees and human-in-the-loop controls.

---

## 3. What Is Explicitly NOT Claimed as Novel

To maintain research integrity and prevent overclaiming, the following are explicitly acknowledged as **established prior art**:
- ❌ Machine Learning or deep learning alone for cloud security.
- ❌ Graph Neural Networks (GNNs) alone for cloud logs.
- ❌ AWS CloudTrail anomaly detection (already widely studied and commercially implemented).
- ❌ Static IAM graph modeling and basic attack-path analysis.
- ❌ Generic alert correlation or rule-based incident grouping.
- ❌ Automated response / SOAR playbooks.
- ❌ Generic composite risk formulas or heuristic alert prioritization.
- ❌ Cross-service signal correlation (documented by AWS and existing commercial SIEMs).

---

## 4. Working Research Contribution

> **Working Hypothesis / Direction:**  
> Investigate an identity-aware and confidence-aware evidence-fusion methodology that combines heterogeneous cloud security signals, relational graph/entity links, and temporal relationships to detect multi-stage threat progression and produce explainable, calibrated security decisions.

*Note:* This is a candidate working research direction subject to empirical validation against baselines, not a final unverified novelty claim.

---

## 5. Research Questions (RQs)

- **RQ1 (Multi-Source Synergy):** Does fusing heterogeneous cloud security signals (audit logs, IAM context, configuration state, vulnerability posture) improve threat detection accuracy compared with isolated single-telemetry detectors?
- **RQ2 (Context & False Positive Reduction):** Does incorporating temporal context and identity/resource relationships reduce false-positive rates compared with individual event-level anomaly detectors?
- **RQ3 (Confidence Calibration & Explainability):** Does confidence-aware evidence calibration provide actionable, transparent evidence attributions that improve operational security decision-making?
- **RQ4 (Progression Latency & Detection):** Can the proposed fusion pipeline identify multi-stage attack chains before data exfiltration occurs with acceptable processing latency?

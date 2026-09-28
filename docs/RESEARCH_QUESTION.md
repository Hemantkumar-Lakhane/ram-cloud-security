# RAM Cloud Security — Working Research Question & Theoretical Framing

## 1. Problem Statement

Modern cloud environments produce high volumes of disparate security signals:
- Deterministic posture scanners (AWS Config, Inspector) identify static vulnerabilities and misconfigurations without knowing if they are actively being exploited.
- UEBA anomaly detectors (CloudTrail analytics) flag statistically unusual API calls but suffer from high false-alarm rates because valid administrative workflows also exhibit unusual patterns.
- Multi-stage cloud attacks advance slowly across distinct phases (Reconnaissance $\to$ Credential Access $\to$ Privilege Escalation $\to$ Defense Evasion $\to$ Exfiltration), leaving individual, low-severity clues across separate AWS services that are rarely connected until data loss occurs.

---

## 2. Working Research Question

> **Primary Research Question:**  
> *"Can multi-source security evidence, combined with temporal and identity-aware behavioral features, detect cloud threat progression more effectively than isolated rule-based or event-level anomaly detection while providing calibrated, explainable confidence?"*

---

## 3. Sub-Questions (RQs) & Hypotheses

- **RQ1 (Multi-Source Synergy):**  
  *Hypothesis:* Fusing deterministic policy findings (Rule Engine) with behavioral anomaly scores (ML Engine) reduces false discovery rates compared to either engine operating in isolation.
- **RQ2 (Temporal & Relational Context):**  
  *Hypothesis:* Tracking sequential API call velocity, service dispersion, and transition probabilities across sliding identity time windows significantly improves detection of multi-stage attack chains over point-in-time event detectors.
- **RQ3 (Confidence Calibration & Explainability):**  
  *Hypothesis:* Probabilistically calibrating composite risk scores and providing top contributing feature attributions improves analyst triage velocity and reduces alert fatigue.
- **RQ4 (Detection Latency):**  
  *Hypothesis:* The hybrid pipeline can identify threat progression before destructive defense evasion or exfiltration occurs with sub-minute processing latency.

---

## 4. What Is Explicitly NOT Claimed as Novel

To maintain strict scientific integrity, the following are acknowledged as **established prior art**:
- ❌ Machine Learning or deep learning alone for cloud security.
- ❌ AWS CloudTrail anomaly detection in isolation.
- ❌ Static IAM graph modeling and basic attack-path analysis.
- ❌ Generic alert correlation or rule-based incident grouping.
- ❌ Automated response / SOAR playbooks.
- ❌ Generic composite risk formulas.

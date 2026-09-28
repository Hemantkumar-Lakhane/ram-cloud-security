# RAM Cloud Security — Standard Evaluation Protocol

## 1. Ground Truth Definitions & Evaluation Units

To prevent ambiguous performance claims, all experiments must report metrics across two standardized evaluation units:

### 1.1 Event-Level Evaluation
- **Evaluation Unit:** Individual normalized CloudTrail events ($N = 2,900$).
- **Definition 1 (All Stratus-Associated):** Positive class = all 1,146 events executed by Stratus (Pure Detonations + Warmup/Cleanup).
- **Definition 2 (Pure Detonations Only):** Positive class = 214 direct attack execution events.
- **Formulas:**
  $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
  $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
  $$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

---

### 1.2 Technique / Incident-Level Evaluation
- **Evaluation Unit:** Distinct adversary detonation runs ($N = 83$ distinct UUID runs).
- **Success Criteria:** A detonation run is considered **detected (True Positive Run)** if at least one high-confidence alert is generated during the sequence.
- **Technique Recall:**
  $$\text{Technique Recall} = \frac{\text{Detected Detonation Runs}}{\text{Total Detonation Runs (83)}}$$

---

## 2. Confusion Matrix Semantics

| Metric | Event-Level Meaning | Incident/Technique Meaning |
|---|---|---|
| **True Positive (TP)** | Model/rule correctly fires an alert on an event belonging to the positive attack set. | Model/rule correctly fires $\ge 1$ alert during a known attack detonation run. |
| **False Positive (FP)** | Model/rule fires an alert on an event belonging to operator Terraform or background AWS activity. | Model/rule fires an alert during purely benign operational periods. |
| **False Negative (FN)** | An attack event occurs without triggering any alert. | An entire attack technique runs from start to finish without triggering any alert. |
| **True Negative (TN)** | Routine event passes without triggering an alert. | Benign operational window passes without triggering any alert. |

---

## 3. Latency & Calibration Metrics

1. **Time to First Detection ($T_{\text{first}}$):**
   $$T_{\text{latency}} = t_{\text{first\_alert}} - t_{\text{attack\_start}}$$
2. **Alert Volume / Suppression Rate:**
   Measures the total number of alerts emitted per 1,000 processed events to quantify analyst alert fatigue.
3. **Brier Score / Calibration Error (for probabilistic models):**
   Measures whether a predicted risk score of 0.80 corresponds to an 80% true positive probability.

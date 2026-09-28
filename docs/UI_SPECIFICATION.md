# RAM Cloud Security — UI Specification & Presentation Layouts

## 1. Design Principles & Aesthetics
- **Visual Style:** Modern, premium dark-mode interface with clean typography, high-contrast severity badging (Red: Critical, Orange: High, Yellow: Medium, Green: Normal), and responsive interactive charts.
- **Goal:** Make complex security research, multi-stage attack timelines, and comparative ML metrics transparent and interactive.

---

## 2. Planned Application Navigation

```
+-----------------------------------------------------------------------------------+
|  [RAM Cloud Security]   Overview | Dataset & EDA | Findings | Investigation | Experiments | Response  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Screen Specifications

### 3.1 Page 1: Overview Dashboard
- **Top Metrics Row:**
  - Total Telemetry Processed (`2,900` events)
  - Security Findings (`42` findings)
  - Critical Alerts (`15` critical)
  - Active Monitored Principals (`13` actors)
- **Visualizations:**
  - Severity Breakdown Donut Chart
  - Recent Findings Table (Title, Severity, Identity, Resource, Time, Action Button)
  - Event Ingestion Rate Sparkline

---

### 3.2 Page 2: Dataset & EDA Explorer
- **Summary Cards:** Dataset Name, Provenance (Invictus-IR / Stratus Red Team), Time Duration (55.5 mins), Services (29), APIs (260).
- **Interactive Chart Grid:**
  - *Panel 1:* 4-Tier Activity Distribution (Pure Detonation vs Warmup vs Operator vs Background).
  - *Panel 2:* Top AWS Services Bar Chart.
  - *Panel 3:* Event Arrival Density Timeline (1-min bins).
  - *Panel 4:* MITRE ATT&CK Tactic Distribution.
  - *Panel 5:* Error Rate & Top Error Codes Breakdown.
- **Dataset Card Drawer:** Embedded view of [`docs/DATASET_CARD.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/DATASET_CARD.md) and provenance details.

---

### 3.3 Page 3: Security Findings Explorer
- **Filter Controls:** Filter by Detection Type (`RULE`, `ML_ANOMALY`, `HYBRID`), Severity, Rule ID, Actor Name.
- **Finding Detail Modal:**
  - Title & Severity Badge
  - Detailed Description & Recommended Action
  - Forensic Evidence JSON Viewer
  - MITRE ATT&CK Tactic & Technique Tag
  - Contributing Features (for ML/Hybrid findings)

---

### 3.4 Page 4: Incident & Attack Investigation Timeline
- **Actor Selector:** Choose an IAM principal (e.g., `bert-jan`, Assumed Role session).
- **Interactive Progression Timeline:**
  - Visual swimlane showing events moving across tactics: Discovery $\to$ Credential Access $\to$ Privilege Escalation $\to$ Defense Evasion.
  - Linked raw event drawer displaying request parameters, source IP, user agent category, and error status.

---

### 3.5 Page 5: Research Experiments & Benchmark Leaderboard
- **Model Comparison Table:**

| Model / Paradigm | Precision | Recall | F1-Score | PR-AUC | Technique Recall | Latency |
|---|---|---|---|---|---|---|
| **Baseline A (Rules Only)** | 54.76% | 2.01% | 0.0387 | — | 20.48% (17/83) | 6.0s |
| **Baseline B (ML Only)** | *[Phase 4]* | *[Phase 4]* | *[Phase 4]* | *[Phase 4]* | *[Phase 4]* | *[Phase 4]* |
| **Proposed Evidence Fusion** | *[Phase 6]* | *[Phase 6]* | *[Phase 6]* | *[Phase 6]* | *[Phase 6]* | *[Phase 6]* |

- **Interactive Visualizations:** Confusion Matrix Heatmap, Precision-Recall Curves, Ablation Study Comparison Bars.

---

### 3.6 Page 6: Safe Response Orchestrator (Policy-Gated)
- **Response Queue:** Planned containment actions generated from findings.
- **Safety Indicators:** `DRY_RUN = True` badge, Simulated Action Log, Required Human Authorization PIN/Token.

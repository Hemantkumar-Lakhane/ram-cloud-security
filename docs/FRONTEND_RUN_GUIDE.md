# RAM Cloud Security — Frontend Application Run Guide

## 1. Overview & Live Server Access

The **RAM Cloud Security** research and operations frontend is a React 19 + TypeScript web application powered by Vite, implementing the approved Anti-Slop enterprise design system.

- **Local Development URL:** [`http://localhost:5173/`](http://localhost:5173/)
- **Build Target:** Production static bundle under `frontend/dist/`
- **Design Standard:** Neutral Light Surfaces (`#F9FAFB`), HSL Semantic Badging, Zero Neon/AI-Slop

---

## 2. Quick Start Commands

```bash
# 1. Export the latest telemetry, findings, and figures to frontend bundles
python scripts/export_frontend_data.py

# 2. Navigate to frontend directory
cd frontend

# 3. Install NPM dependencies
npm install

# 4. Start the local development server (live on port 5173)
npm run dev

# 5. Build for production verification
npm run build
```

---

## 3. Implemented Features & Route Directory

### 3.1 Security Domain
- **`/security/overview` (Security Overview Dashboard):** High-signal posture summary featuring the dynamic 1-minute event arrival velocity density graph (Figure 09), 4-tier activity distribution (Figure 01), active findings counter, and live triage table.
- **`/security/findings` (Findings Workspace):** Multi-filter searchable triage table of all 42 Baseline A detections with severity chips (`Critical`, `High`, `Medium`, `Low`) and rule domain selectors.
- **`/security/findings/:id` (Forensic Detail Drawer):** $640\text{px}$ slide-over panel displaying detection rationale, rule evidence, actor context, raw normalized JSON payload, and Dry Run response preview.
- **`/security/investigation` (Incident Investigation):** Multi-signal temporal correlation linking IAM principals (`IAMUser-01`, `Role-01`) to Figure 14 (Pure Detonation Timeline) and Figure 12 (Service Heatmap) with explicit emulation run disambiguation disclaimers.

### 3.2 Environment Domain
- **`/environment/assets` (Assets Inventory):** Inventory of discovered AWS cloud resources (EC2, S3, IAM, KMS, SSM) with event volumes and associated finding counts.
- **`/environment/identities` (Identities Monitor):** 14 sanitized IAM principals (`Role-01` .. `Role-10`, `IAMUser-01`, `IAMUser-02`) with embedded Figure 13 dual-panel interaction matrix (Raw Counts vs. Access Profile %).
- **`/environment/workloads` & `/environment/network`:** Transparent future module banners for Phase 7 eBPF container runtime monitoring and VPC flow log analysis.

### 3.3 Posture Domain
- **`/posture/misconfigurations`:** Cloud configuration drift findings from `RULE-CFG-001` through `RULE-CFG-004`.
- **`/posture/vulnerabilities`:** Not Connected state for AWS Inspector CVE scanning.
- **`/posture/compliance`:** Compliance mapping framework for CIS AWS Foundations Benchmark.
- **`/posture/exposure`:** Public exposure alerts from `RULE-EXP-001`.

### 3.4 Detection Domain
- **`/detection/events` (Telemetry Event Explorer):** Stream explorer across 2,900 normalized CloudTrail events with progressive disclosure of raw parameters.
- **`/detection/threats` (Threat Activity):** Detailed inventory of the 83 Stratus Red Team emulation runs documenting the 17 detected vs 66 missed runs.

### 3.5 Research Domain
- **`/research/dataset` (Dataset Card):** Comprehensive dataset provenance, 4-tier operational breakdown, and anti-leakage rules.
- **`/research/eda` (EDA Figures Gallery):** Interactive gallery displaying all **14 approved high-DPI figures** organized in 6 thematic tabs with raw field tags, calculation formulas, and security takeaways.
- **`/research/experiments` (Benchmark Leaderboard):** Side-by-side benchmark matrix comparing Baseline A (Rules Only: 54.76% Precision, 2.01% Recall, 20.48% Technique Recall) against future ML/Fusion paradigms.
- **`/research/evaluation` (Evaluation Protocol):** Multi-ground-truth scientific documentation for Definitions 1, 2, and 3.

### 3.6 Response & Administration Domains
- **`/response/center` (Safe Response Center):** Policy-gated remediation queue featuring the **Human Authorization Modal** with explicit `DRY RUN MODE` banner, parameter diff, and mandatory audit justification input.
- **`/response/history` (Action History):** Immutable local log of simulated response actions.
- **`/admin/integrations`, `/admin/policies`, `/admin/settings`:** Telemetry connectors, rule toggles, and environment configurations.

---

## 4. Key Keyboard Shortcuts & Interactions

- **`Ctrl+K` / `Cmd+K`:** Global Command Palette modal for instant search and navigation across telemetry, findings, identities, and EDA figures.
- **`Esc`:** Close active drawer or modal dialog.
- **Row Click:** Opens the Forensic Detail Drawer for any security finding or the JSON Inspector for any telemetry event.

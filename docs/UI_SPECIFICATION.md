# RAM Cloud Security — Master UI/UX Product Design Specification

## 1. Executive Summary & Design System Architecture

RAM Cloud Security is an enterprise-grade cloud security operations and machine learning research platform. The user experience is built around the **Anti-Slop Design Doctrine**: calm, high-contrast, data-dense, technical, and trustworthy.

The full UI/UX design specification is organized into six core architectural documents:

1. [`docs/UI_UX_SYSTEM.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_UX_SYSTEM.md) — Visual design foundation, neutral light surfaces, strict semantic palette, typography scale, and 8-state handling matrix.
2. [`docs/UI_INFORMATION_ARCHITECTURE.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_INFORMATION_ARCHITECTURE.md) — 7-domain hierarchy, complete route map, shell anatomy, and universal search/filter contracts.
3. [`docs/UI_SCREEN_SPECIFICATION.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_SCREEN_SPECIFICATION.md) — Exhaustive screen layouts, component hierarchies, and interactive behaviors for all 15 screens (A through O).
4. [`docs/UI_COMPONENT_SYSTEM.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_COMPONENT_SYSTEM.md) — Reusable component contracts (`SeverityBadge`, `DataTable`, `DetailDrawer`, `FigureCard`, `ActionModal`, `DualPanelHeatmap`).
5. [`docs/UI_DATA_CONTRACTS.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_DATA_CONTRACTS.md) — End-to-end data provenance connecting UI metrics to active JSON/pipeline sources with dynamic calculation rules.
6. [`docs/UI_FUTURE_MODULES.md`](file:///c:/Users/lakha/ml_ram_antivirous/docs/UI_FUTURE_MODULES.md) — Research integrity protocol for representing future modules (`Not Evaluated`, `Not Connected`, `Coming Soon`) without fake data.

---

## 2. Complete Navigation Taxonomy (7 Operational Domains)

```
RAM Cloud Security Console
├── 1. SECURITY
│   ├── Overview Dashboard (/security/overview) [Active]
│   ├── Security Findings (/security/findings) [Active]
│   └── Incident Investigation (/security/investigation) [Active]
├── 2. ENVIRONMENT
│   ├── Assets Inventory (/environment/assets) [Connected]
│   ├── Identities & IAM (/environment/identities) [Connected]
│   ├── Workloads (/environment/workloads) [Coming Soon]
│   └── Network & VPC (/environment/network) [Coming Soon]
├── 3. POSTURE
│   ├── Misconfigurations (/posture/misconfigurations) [Active]
│   ├── Vulnerabilities (/posture/vulnerabilities) [Not Connected]
│   ├── Compliance Frameworks (/posture/compliance) [Coming Soon]
│   └── Exposure (/posture/exposure) [Active]
├── 4. DETECTION
│   ├── Event Telemetry Explorer (/detection/events) [Active]
│   ├── Threat Activity (/detection/threats) [Active]
│   └── Attack Sequences (/detection/sequences) [Not Evaluated]
├── 5. RESEARCH
│   ├── Dataset Provenance (/research/dataset) [Active]
│   ├── EDA Explorer (14 Figures) (/research/eda) [Active]
│   ├── Experiments & Benchmark (/research/experiments) [Active]
│   └── Evaluation Protocol (/research/evaluation) [Active]
├── 6. RESPONSE
│   ├── Response Center (/response/center) [Active (Simulated)]
│   └── Action Audit History (/response/history) [Active (Simulated)]
└── 7. ADMINISTRATION
    ├── Telemetry Integrations (/admin/integrations) [Active]
    ├── Detection Policies (/admin/policies) [Active]
    └── System Settings (/admin/settings) [Active]
```

---

## 3. Core Investigation & Research User Journeys

### 3.1 Security Analyst Triage Journey
$$\text{Overview Dashboard} \longrightarrow \text{Finding Drawer} \longrightarrow \text{Rule Evidence} \longrightarrow \text{Identity Profile (Fig 13)} \longrightarrow \text{Preview Response [Dry Run]} \longrightarrow \text{Action History}$$

### 3.2 Academic / Researcher Evaluation Journey
$$\text{Dataset Provenance} \longrightarrow \text{EDA Gallery (14 Figs)} \longrightarrow \text{Baseline A Benchmark} \longrightarrow \text{Evaluation Metrics Protocol} \longrightarrow \text{Phase 4 ML Roadmap}$$

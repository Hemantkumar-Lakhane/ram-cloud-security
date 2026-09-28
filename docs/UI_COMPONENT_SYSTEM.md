# RAM Cloud Security — UI Component System Specification

This document defines the reusable UI component primitives, design contracts, anatomy, and interaction states for the frontend architecture.

---

## 1. Core Component Hierarchy

```
UI Component System
├── 1. Data Display & Tables
│   ├── DataTable (Virtualized, sortable, expandable)
│   ├── MetricChip / StatStrip
│   ├── KeyValueGrid
│   └── JsonViewer (Syntax-highlighted forensic inspector)
├── 2. Badges, Tags & Indicators
│   ├── SeverityBadge (Critical, High, Medium, Low, Info)
│   ├── StateBadge (Active, Empty, Not Connected, Not Evaluated, etc.)
│   ├── ProvenancePill (Pure Detonation, Warmup, Operator, Background)
│   └── ConfidenceMeter (0.00 – 1.00 numeric & micro-bar)
├── 3. Overlays & Navigation
│   ├── DetailDrawer (Slide-over forensic panel, 640px)
│   ├── ActionModal (Policy-gated approval dialog)
│   ├── BreadcrumbBar
│   └── CommandPaletteModal (Ctrl+K omni-search)
├── 4. Visualizations & Media
│   ├── FigureCard (Wrapper for 300 DPI research figures with zoom & metadata)
│   ├── TacticSwimlane (Interactive ATT&CK progression timeline)
│   ├── DualPanelHeatmap (Raw counts vs normalized % matrix)
│   └── IngestionSparkline (1-minute density graph)
└── 5. Form & Filter Controls
    ├── FilterBar (Multi-select dropdowns, time picker, search query)
    ├── SegmentedToggle (Tabbed views, table/graph toggles)
    └── ResponseButton (Primary, Secondary, Destructive, Dry-Run)
```

---

## 2. Component Specifications

### 2.1 `SeverityBadge`
- **Anatomy:** `[Glyph] [Severity Text]`
- **Dimensions:** Height $22\text{px}$, Padding $2\text{px } 8\text{px}$, Font size $11\text{px}$, Weight $600$.
- **Variants:**
  - `CRITICAL`: `◆ CRITICAL` (Text: `#991B1B`, BG: `#FEF2F2`, Border: `#F87171`)
  - `HIGH`: `▲ HIGH` (Text: `#9A3412`, BG: `#FFF7ED`, Border: `#FDBA74`)
  - `MEDIUM`: `● MEDIUM` (Text: `#854D0E`, BG: `#FEFCE8`, Border: `#FDE047`)
  - `LOW`: `■ LOW` (Text: `#1E40AF`, BG: `#EFF6FF`, Border: `#93C5FD`)
  - `INFO`: `○ INFO` (Text: `#374151`, BG: `#F3F4F6`, Border: `#D1D5DB`)

---

### 2.2 `DataTable`
- **Features:** Virtualized row rendering ($100\text{k}+$ event capacity), sticky headers, multi-column sorting, row selection checkboxes, row expansion for nested JSON payloads, pagination ($25$, $50$, $100$ per page).
- **Styling:**
  - Header Row: Background `#F9FAFB`, Text `#4B5563` ($12\text{px}$ uppercase bold), Border-bottom `1px solid #E5E7EB`.
  - Body Rows: Background `#FFFFFF`, Hover `#F9FAFB`, Selected `#EFF6FF`, Height $40\text{px}$ (Dense).
  - Cell Typography: Tabular numeric alignment for timestamps, counts, and IDs.

---

### 2.3 `DetailDrawer` (Forensic Inspector)
- **Anatomy:**
  - Header: Breadcrumb trail, Finding ID, Severity Badge, Close Button (`Esc`).
  - Scrollable Body: Tabbed sections (*Overview*, *Evidence*, *Raw Event JSON*, *Response Actions*).
  - Footer (Fixed): Primary Action (`Preview Response`), Secondary Action (`Suppress Finding`).
- **Width:** Fixed $640\text{px}$ on desktop ($w \ge 1280\text{px}$); full-width on mobile ($w < 768\text{px}$).

---

### 2.4 `FigureCard` (Research EDA Wrapper)
- **Anatomy:**
  - Card Header: Figure Number & Title (e.g., `Figure 05: Stratus-Associated Activity Breakdown`), Research Section Tag, Provenance Status.
  - Image Canvas: Responsive high-DPI image viewer with click-to-expand lightbox.
  - Metadata Drawer / Caption:
    - *Raw Telemetry Fields Used:* (`userAgent`, `eventName`, `eventSource`).
    - *Statistical Calculation:* Dynamic aggregation formula.
    - *Security / Research Finding:* Scientific takeaway text.
- **Styling:** Border `1px solid #E5E7EB`, Background `#FFFFFF`, Shadow `shadow-sm`.

---

### 2.5 `ActionModal` (Human-in-the-Loop Response Gate)
- **Purpose:** Prevents accidental or unauthenticated execution of response actions.
- **Anatomy:**
  - Safety Warning Banner: `DRY RUN MODE — Simulation Only`.
  - Action Summary: Target Resource ARN, Action Name (`StartLogging`), Impact Summary.
  - Execution Diff: Visual before/after parameter state.
  - Mandatory Audit Reason: Required text input (`"Triage for unauthorized StopLogging call by IAMUser-01"`).
  - Confirmation Button: `Confirm & Simulate Response [Dry Run]`.

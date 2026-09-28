# Comprehensive Exploratory Data Analysis (EDA) Report

## 1. Dataset Overview & Schema Profiling

- **Dataset:** Stratus Red Team CloudTrail Attack Dataset (`invictus-ir/aws_dataset`)
- **Total Records:** `2,900` CloudTrail events (55 JSON log files)
- **Time Range:** `2023-07-10 11:42:18 UTC` to `2023-07-10 12:37:50 UTC` (55.5 minutes)
- **Core Normalization:** 100% normalized into [`NormalizedEvent`](file:///c:/Users/lakha/ml_ram_antivirous/src/common/models.py#L19-L46) schema.

### Data Completeness & Missing Value Analysis:
- `event_id`, `timestamp`, `event_source`, `event_name`, `account_id`, `source_ip`, `user_agent`: **0.0% missing** (present on all 2,900 records).
- `actor_name`: **2.62% missing** (corresponding to internal AWSService background calls).
- `actor_type`: **1.45% missing** (`IAMUser`: 2,748, `AssumedRole`: 76, `AWSService`: 34).
- `error_code`: **89.66% null** (reflects successful API calls; 300 total calls resulted in errors).

---

## 2. Research Visualizations & Analysis

### Figure 1: Operational Activity Tier Distribution
![Figure 1: Operational Activity Tier Distribution](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/01_dataset_activity_distribution.png)
* **What it shows:** Breakdown of the 2,900 events into the four operational tiers identified during the label audit.
* **Findings:** Pure Detonations represent 214 events (7.4%), Stratus Terraform Warmup/Cleanup represents 932 events (32.1%), Operator Terraform represents 1,006 events (34.7%), and AWS Background/Internal represents 748 events (25.8%).

---

### Figure 2: Top AWS Services by Event Volume
![Figure 2: Top AWS Services](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/02_service_distribution.png)
* **What it shows:** The top 10 AWS services generating telemetry.
* **Findings:** `ec2.amazonaws.com` dominates with 892 events (30.8%), followed by `ssm.amazonaws.com` (488 events / 16.8%), `iam.amazonaws.com` (398 events / 13.7%), `s3.amazonaws.com` (271 events / 9.3%), and `kms.amazonaws.com` (240 events / 8.3%).

---

### Figure 3: Top API Actions Across Entire Dataset
![Figure 3: Top API Actions](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/03_api_distribution.png)
* **What it shows:** Top 15 most frequent API actions.
* **Findings:** `Decrypt` (178), `DescribeRouteTables` (163), `GetUser` (130), `DescribeParameters` (122), and `ListTagsForResource` (88) represent standard infrastructure and discovery operations.

---

### Figure 4: Pure Attack Detonation API Actions
![Figure 4: Pure Attack Detonation APIs](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/04_pure_detonation_api_distribution.png)
* **What it shows:** The 214 explicit attack detonation API calls.
* **Findings:** Heavy concentration in reconnaissance (`DescribeAccountAttributes`: 34, `DescribeInstanceInformation`: 27) and credential harvesting (`GetPasswordData`: 29, `GetSecretValue`: 20, `AssumeRole`: 23).

---

### Figure 5: Stratus-Associated Activity Mapped to MITRE ATT&CK Tactics
![Figure 5: MITRE ATT&CK Mapping](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/05_attack_technique_distribution.png)
* **What it shows:** Two-panel comparative breakdown separating pure adversarial detonation actions mapped to standard MITRE ATT&CK tactics (Panel A, $N=214$) from prerequisite infrastructure setup and teardown APIs (Panel B, $N=932$).
* **Findings:** Pure detonations heavily concentrate in Discovery (87 calls) and Credential Access (51 calls), while prerequisite orchestration focuses on resource lifecycle APIs (`PutParameters`, `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`).

---

### Figure 6: IAM Actor Distribution (Sanitized Identifiers)
![Figure 6: Identity Distribution](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/06_identity_distribution.png)
* **What it shows:** Event volume per IAM principal, using deterministic neutral sanitization tokens (`Role-01`, `Role-02`, `IAMUser-01`, `AWSService-01`) to prevent exposing long raw session identifiers.
* **Findings:** `IAMUser-01` generated 2,642 events (91.1%), `IAMUser-02` generated 105 events (3.6%), while 10 distinct assumed-role sessions executed runner and service-linked automation tasks.

---

### Figure 7: Success vs. Error Rate
![Figure 7: Success vs Error Rate](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/07_success_error_distribution.png)
* **What it shows:** Overall ratio of successful API requests (89.7% / 2,600 calls) vs errored requests (10.3% / 300 calls).

---

### Figure 8: Breakdown of Top Error Codes
![Figure 8: Error Types Breakdown](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/08_error_type_distribution.png)
* **What it shows:** Top error codes generated during adversarial detonations and probing ($N=300$).
* **Findings:** `ThrottlingException` (102 calls / 34.0%) occurred during high-velocity burst detonations; `Client.UnauthorizedOperation` (44 calls / 14.7%) and `AccessDenied` (16 calls / 5.3%) occurred during privilege probing.

---

### Figure 9: Overall Event Arrival Rate Density
![Figure 9: Event Timeline](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/09_event_timeline.png)
* **What it shows:** Event frequency binned in 1-minute intervals across the 55.5-minute capture.
* **Findings:** Distinct bursts exceeding 120–160 events/minute represent automated detonation loops, contrasting with baseline steady-state rates (<10 events/min).

---

### Figure 10: Multi-Tier Activity Volume Over Timeline
![Figure 10: Multi-Tier Activity Timeline](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/10_activity_timeline.png)
* **What it shows:** Stacked area volume showing when Pure Detonations, Warmup/Cleanup, Operator Terraform, and Background events occurred across 2-minute bins.
* **Findings:** Detonations are interspersed between Terraform warmup and teardown phases, reflecting realistic adversary lifecycle testing.

---

### Figure 11: Provenance & Operational Tool Attribution Breakdown
![Figure 11: Overlap Quantification](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/11_stratus_terraform_overlap.png)
* **What it shows:** Explicit quantification of the four mutually exclusive operational subsets across the 2,900 events.
* **Findings:** 932 events share both Stratus and Terraform signatures due to prerequisite infrastructure orchestration, 1,006 events represent standalone operator Terraform actions, 748 events represent AWS background services, and 214 events represent pure detonations.

---

### Figure 12: Top AWS Services Activity Heatmap
![Figure 12: Service Heatmap](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/12_service_activity_heatmap.png)
* **What it shows:** 5-minute temporal activity across the top 8 AWS services.
* **Findings:** EC2 and SSM maintain persistent activity, while Secrets Manager, KMS, and CloudTrail exhibit focused burst spikes during specific attack detonations.

---

### Figure 13: Principal-to-Service Interaction Matrix (Raw Counts vs Profile Distribution)
![Figure 13: Identity-Service Matrix](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/13_identity_service_relationship.png)
* **What it shows:** Dual-panel interaction matrix: Panel A displays raw event co-occurrence counts, while Panel B displays the row-normalized percentage distribution of each actor's activity across AWS services ($\sum = 100\%$).
* **Findings:** Establishes distinct service-access behavioral profiles for each principal, directly laying the empirical foundation for identity-aware baseline modeling.

---

### Figure 14: Pure Detonation Activity Timeline by ATT&CK-Mapped Category
![Figure 14: Attack Detonation Trace](file:///c:/Users/lakha/ml_ram_antivirous/reports/figures/eda/14_attack_sequence_timeline.png)
* **What it shows:** Chronological timeline of the 214 pure attack detonation events plotted against their corresponding MITRE ATT&CK tactic categories.
* **Research Integrity Note:** These events represent discrete, independent Stratus Red Team emulation runs executed sequentially across the capture window. Chronological ordering reflects detonation execution order and does not establish a single coordinated multi-stage APT attack campaign.

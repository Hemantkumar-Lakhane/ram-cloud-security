import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { EDASummary, BaselineMetrics } from '../types';
import { FigureCard } from '../components/FigureCard';
import { FutureStateBanner } from '../components/Badges';

export const DatasetProvenance: React.FC = () => {
  const [eda, setEDA] = useState<EDASummary | null>(null);

  useEffect(() => {
    dataService.getEDASummary().then(setEDA);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Research Dataset Card & Provenance</h1>
          <span className="page-description">
            Scientific specification and audited operational semantics of the Stratus Red Team CloudTrail dataset.
          </span>
        </div>
        <span className="badge badge-active">Invictus-IR / AWS Dataset</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Total Telemetry</span>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.total_records.toLocaleString() : '2,900'} Events
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>55 Raw JSON Files</span>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Time Duration</span>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.time_span.duration_minutes : '55.5'} Minutes
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>Continuous Capture</span>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Distinct Services</span>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.distinct_counts.services : '29'} Services
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>Top: EC2, SSM, IAM</span>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Distinct APIs</span>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.distinct_counts.event_names : '260'} API Actions
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>14 Sanitized Actors</span>
        </div>
      </div>

      {/* 4-Tier Breakdown Card */}
      <div className="card">
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600 }}>Audited 4-Tier Operational Activity Breakdown</span>
        </div>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Operational Tier</th>
                <th>Event Count</th>
                <th>Percentage</th>
                <th>Provenance & Description</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong style={{ color: '#dc2626' }}>Tier 1: Pure Detonation</strong></td>
                <td><strong>214</strong></td>
                <td>7.38%</td>
                <td>Direct adversarial API execution during Stratus detonate phase (StopLogging, GetPasswordData).</td>
              </tr>
              <tr>
                <td><strong style={{ color: '#ea580c' }}>Tier 2: Stratus Warmup/Cleanup</strong></td>
                <td><strong>932</strong></td>
                <td>32.14%</td>
                <td>Terraform-orchestrated prerequisite infrastructure creation and post-run teardown.</td>
              </tr>
              <tr>
                <td><strong style={{ color: '#2563eb' }}>Tier 3: Operator Terraform</strong></td>
                <td><strong>1,006</strong></td>
                <td>34.69%</td>
                <td>Independent lab environment management and infrastructure provisioning.</td>
              </tr>
              <tr>
                <td><strong style={{ color: '#4b5563' }}>Tier 4: AWS Background/Internal</strong></td>
                <td><strong>748</strong></td>
                <td>25.79%</td>
                <td>Internal AWS service calls, KMS rotations, and routine cloud maintenance.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export const EDAExplorer: React.FC = () => {
  const [tab, setTab] = useState<'overview' | 'services' | 'tactics' | 'identity' | 'errors' | 'timeline'>('overview');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Exploratory Data Analysis (EDA) Gallery</h1>
          <span className="page-description">
            Interactive research explorer for the 14 approved publication-grade EDA figures generated at 300 DPI.
          </span>
        </div>
      </div>

      {/* 6 Thematic Gallery Tabs */}
      <div className="tabs-nav">
        <button className={`tab-button ${tab === 'overview' ? 'active' : ''}`} onClick={() => setTab('overview')}>
          1. Overview (Fig 01, 09, 10)
        </button>
        <button className={`tab-button ${tab === 'services' ? 'active' : ''}`} onClick={() => setTab('services')}>
          2. Services & APIs (Fig 02, 03, 04)
        </button>
        <button className={`tab-button ${tab === 'tactics' ? 'active' : ''}`} onClick={() => setTab('tactics')}>
          3. Tactics & Provenance (Fig 05, 11)
        </button>
        <button className={`tab-button ${tab === 'identity' ? 'active' : ''}`} onClick={() => setTab('identity')}>
          4. Identity & Access (Fig 06, 13)
        </button>
        <button className={`tab-button ${tab === 'errors' ? 'active' : ''}`} onClick={() => setTab('errors')}>
          5. Error Dynamics (Fig 07, 08)
        </button>
        <button className={`tab-button ${tab === 'timeline' ? 'active' : ''}`} onClick={() => setTab('timeline')}>
          6. Timelines & Detonations (Fig 12, 14)
        </button>
      </div>

      {/* Figures Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))', gap: '20px' }}>
        {tab === 'overview' && (
          <>
            <FigureCard
              figureNumber="Figure 01"
              title="Operational Activity Tier Breakdown"
              imageSrc="/figures/eda/01_dataset_activity_distribution.png"
              fieldsUsed={['userAgent', 'event_id']}
              calculationFormula="Regex pattern matching for Stratus UUIDs, Terraform tokens, and AWS internal services."
              securityTakeaway="Classifies the dataset into 4 mutually exclusive tiers (214 Detonations, 932 Warmup, 1,006 Operator, 748 Background)."
            />
            <FigureCard
              figureNumber="Figure 09"
              title="Event Arrival Rate (1-Min Velocity Density)"
              imageSrc="/figures/eda/09_event_timeline.png"
              fieldsUsed={['timestamp', 'event_id']}
              calculationFormula="1-minute time bin event count density resampling."
              securityTakeaway="Reveals distinct automated burst spikes exceeding 120-160 events/min during adversary detonations."
            />
            <FigureCard
              figureNumber="Figure 10"
              title="Multi-Tier Activity Over Time"
              imageSrc="/figures/eda/10_activity_timeline.png"
              fieldsUsed={['timestamp', 'tier']}
              calculationFormula="2-minute time bin stacked event counts cross-tabulated by operational tier."
              securityTakeaway="Demonstrates that adversary detonations are interspersed between warmup and cleanup phases."
            />
          </>
        )}

        {tab === 'services' && (
          <>
            <FigureCard
              figureNumber="Figure 02"
              title="Top AWS Services Volume"
              imageSrc="/figures/eda/02_service_distribution.png"
              fieldsUsed={['event_source']}
              calculationFormula="Value counts of event_source sorted descending across all 2,900 events."
              securityTakeaway="EC2 (892 calls) and SSM (488 calls) dominate total telemetry volume."
            />
            <FigureCard
              figureNumber="Figure 03"
              title="Top Dataset-Wide API Actions"
              imageSrc="/figures/eda/03_api_distribution.png"
              fieldsUsed={['event_name']}
              calculationFormula="Value counts of top 15 event_name across entire dataset."
              securityTakeaway="Infrastructure maintenance and discovery calls constitute the bulk of dataset activity."
            />
            <FigureCard
              figureNumber="Figure 04"
              title="Pure Detonation API Actions (Tier 1)"
              imageSrc="/figures/eda/04_pure_detonation_api_distribution.png"
              fieldsUsed={['event_name', 'tier']}
              calculationFormula="Value counts of event_name filtered to Tier 1 Pure Detonations (N=214)."
              securityTakeaway="Pure attack calls concentrate heavily in reconnaissance and credential harvesting."
            />
          </>
        )}

        {tab === 'tactics' && (
          <>
            <FigureCard
              figureNumber="Figure 05"
              title="Stratus Activity: ATT&CK Tactics vs Operational Setup"
              imageSrc="/figures/eda/05_attack_technique_distribution.png"
              fieldsUsed={['event_name', 'tier']}
              calculationFormula="2-Panel split: Panel A (MITRE ATT&CK Tactics for Pure Detonations) vs Panel B (Prerequisite Infrastructure APIs)."
              securityTakeaway="Separates standard adversarial tactics (Discovery, Credential Access) from Terraform lifecycle orchestration."
            />
            <FigureCard
              figureNumber="Figure 11"
              title="Provenance & Operational Tool Attribution Breakdown"
              imageSrc="/figures/eda/11_stratus_terraform_overlap.png"
              fieldsUsed={['userAgent']}
              calculationFormula="Mutually exclusive tool overlap categorization across the 2,900 events."
              securityTakeaway="Quantifies the 932 dual-signature events resulting from Stratus-orchestrated Terraform."
            />
          </>
        )}

        {tab === 'identity' && (
          <>
            <FigureCard
              figureNumber="Figure 06"
              title="IAM Principal Distribution (Sanitized Identifiers)"
              imageSrc="/figures/eda/06_identity_distribution.png"
              fieldsUsed={['actor_name', 'actor_type']}
              calculationFormula="Deterministic sanitization mapping raw actors to neutral IDs (Role-01, IAMUser-01)."
              securityTakeaway="IAMUser-01 accounts for 91.1% of activity, supported by 10 distinct assumed-role sessions."
            />
            <FigureCard
              figureNumber="Figure 13"
              title="Principal-to-Service Interaction Matrix (Dual-Panel)"
              imageSrc="/figures/eda/13_identity_service_relationship.png"
              fieldsUsed={['actor_name', 'event_source']}
              calculationFormula="Panel A: Raw event counts; Panel B: Row-normalized percentage access distribution."
              securityTakeaway="Establishes unique service access profiles per actor, forming the foundation for identity-aware baseline modeling."
            />
          </>
        )}

        {tab === 'errors' && (
          <>
            <FigureCard
              figureNumber="Figure 07"
              title="API Execution Success vs Error Rate"
              imageSrc="/figures/eda/07_success_error_distribution.png"
              fieldsUsed={['is_error', 'error_code']}
              calculationFormula="Binary error rate evaluation across all 2,900 records."
              securityTakeaway="89.7% of calls succeeded; 10.3% (300 calls) generated errors during reconnaissance and burst loops."
            />
            <FigureCard
              figureNumber="Figure 08"
              title="Top AWS Error Codes Breakdown"
              imageSrc="/figures/eda/08_error_type_distribution.png"
              fieldsUsed={['error_code']}
              calculationFormula="Frequency counts of distinct AWS error codes across the 300 error events."
              securityTakeaway="ThrottlingException (102 calls) occurred during high-velocity bursts; UnauthorizedOperation (44 calls) during probing."
            />
          </>
        )}

        {tab === 'timeline' && (
          <>
            <FigureCard
              figureNumber="Figure 12"
              title="Cross-Service Activity Intensity Heatmap"
              imageSrc="/figures/eda/12_service_activity_heatmap.png"
              fieldsUsed={['timestamp', 'event_source']}
              calculationFormula="2D temporal matrix of event density across top 8 services in 5-minute bins."
              securityTakeaway="Highlights temporal surges in Secrets Manager, KMS, and CloudTrail during focused detonations."
            />
            <FigureCard
              figureNumber="Figure 14"
              title="Pure Detonation Activity Timeline by ATT&CK Category"
              imageSrc="/figures/eda/14_attack_sequence_timeline.png"
              fieldsUsed={['timestamp', 'event_name', 'mitre_tactic']}
              calculationFormula="Chronological sequence of 214 pure detonations mapped to MITRE tactics."
              securityTakeaway="Shows individual detonation runs executed chronologically across the capture window."
            />
          </>
        )}
      </div>
    </div>
  );
};

export const ExperimentsBenchmark: React.FC = () => {
  const [baseline, setBaseline] = useState<BaselineMetrics | null>(null);

  useEffect(() => {
    dataService.getBaselineMetrics().then(setBaseline);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Scientific Experiments & Benchmark Leaderboard</h1>
          <span className="page-description">
            Comparative evaluation of detection paradigms evaluated against the Stratus Red Team CloudTrail dataset.
          </span>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600 }}>Paradigm Performance Comparison</span>
        </div>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Detection Paradigm</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>Technique Recall</th>
                <th>Detection Latency</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Baseline A (Rules Only)</strong></td>
                <td><strong>{baseline ? (baseline.event_level_metrics.precision * 100).toFixed(2) : '54.76'}%</strong></td>
                <td><strong>{baseline ? (baseline.event_level_metrics.recall * 100).toFixed(2) : '2.01'}%</strong></td>
                <td><strong>{baseline ? baseline.event_level_metrics.f1_score.toFixed(4) : '0.0387'}</strong></td>
                <td><strong>20.48% (17/83 runs)</strong></td>
                <td><strong>6.0s</strong></td>
                <td><span className="badge badge-active">Completed & Audited</span></td>
              </tr>
              <tr style={{ background: '#f8fafc' }}>
                <td><strong>Baseline B (Statistical Anomaly)</strong></td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td><span className="badge badge-not-evaluated">Phase 4 Target</span></td>
              </tr>
              <tr style={{ background: '#f8fafc' }}>
                <td><strong>Baseline C (Behavioral Sequence)</strong></td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td><span className="badge badge-not-evaluated">Phase 5 Target</span></td>
              </tr>
              <tr style={{ background: '#f8fafc' }}>
                <td><strong>Proposed Evidence Fusion (RAM Antivirus)</strong></td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
                <td><span className="badge badge-not-evaluated">Phase 6 Target</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <FutureStateBanner
        title="Machine Learning & Evidence Fusion Roadmap"
        phase="Phase 4–6 Pipeline"
        description="Phase 4 feature engineering and unsupervised anomaly modeling will populate Baseline B metrics. Multi-source Bayesian/confidence evidence fusion will be evaluated in Phase 6."
        requiredInput="Sliding temporal window tensors, identity transition matrices, confidence-weighted rule outputs."
      />
    </div>
  );
};

export const EvaluationProtocol: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Evaluation Methodology & Protocols</h1>
          <span className="page-description">
            Scientific evaluation standards, multi-ground-truth definitions, and metrics calculation guidelines.
          </span>
        </div>
      </div>

      <div className="card" style={{ padding: '16px' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Ground Truth Definitions & Evaluation Boundaries</h3>
        <ul style={{ paddingLeft: '20px', fontSize: '13px', color: '#475569', lineHeight: '1.6' }}>
          <li>
            <strong>Definition 1 (Stratus-Associated Activity, N=1,146):</strong> Treats all events generated by the Stratus tool (detonations + prerequisite warmup/cleanup) as positive ground truth. Baseline A achieved 54.76% precision and 2.01% recall under this definition.
          </li>
          <li>
            <strong>Definition 2 (Pure Detonations Only, N=214):</strong> Restricts positive ground truth strictly to the direct detonate phase API executions. Baseline A achieved 30.95% precision and 6.07% recall.
          </li>
          <li>
            <strong>Definition 3 (Technique-Run Level, N=83 runs):</strong> Evaluates whether at least one security finding was generated during each discrete 83 detonation UUID runs. Baseline A achieved 20.48% technique recall (17/83 runs detected).
          </li>
        </ul>
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { EDASummary, BaselineMetrics, TelemetryEvent, IdentityRecord, ThreatRun } from '../types';
import { FigureCard } from '../components/FigureCard';
import { InteractiveTimeline } from '../components/charts/InteractiveTimeline';
import { InteractiveTierDonut } from '../components/charts/InteractiveTierDonut';
import { InteractiveIdentityMatrix } from '../components/charts/InteractiveIdentityMatrix';
import { InteractiveServiceDistribution } from '../components/charts/InteractiveServiceDistribution';
import { InteractiveThreatTimeline } from '../components/charts/InteractiveThreatTimeline';
import { LayoutGrid, BarChart2 } from 'lucide-react';

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

      {/* Anti-Leakage Rules */}
      <div className="card" style={{ borderLeft: '4px solid #dc2626' }}>
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#991b1b' }}>Scientific Anti-Leakage Protocol</span>
        </div>
        <div className="card-body" style={{ fontSize: '12px', color: '#374151', lineHeight: '1.6' }}>
          To prevent synthetic label leakage and maintain rigorous scientific validity, ML feature extractors are strictly prohibited from using:
          <ul style={{ paddingLeft: '20px', marginTop: '6px' }}>
            <li><code>userAgent</code> raw strings (which contain explicit <code>stratus-red-team</code> or <code>Terraform</code> signatures).</li>
            <li>Tool identification tokens or synthetic UUID tags.</li>
            <li>Synthetic detonation filenames.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export const EDAExplorer: React.FC = () => {
  const [viewMode, setViewMode] = useState<'interactive' | 'figures'>('interactive');
  const [tab, setTab] = useState<'overview' | 'services' | 'tactics' | 'identity' | 'errors' | 'timeline'>('overview');
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [eda, setEDA] = useState<EDASummary | null>(null);
  const [identities, setIdentities] = useState<IdentityRecord[]>([]);
  const [threatRuns, setThreatRuns] = useState<ThreatRun[]>([]);

  useEffect(() => {
    dataService.getEvents().then(setEvents);
    dataService.getEDASummary().then(setEDA);
    dataService.getIdentities().then(setIdentities);
    dataService.getThreatRuns().then(setThreatRuns);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Exploratory Data Analysis (EDA) & Visual Analytics</h1>
          <span className="page-description">
            Dual-mode research analytics: Real-time dynamic SVG visualizers and 14 publication-grade figures at 300 DPI.
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className={`btn btn-sm ${viewMode === 'interactive' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('interactive')}
            style={{ gap: '6px' }}
          >
            <BarChart2 size={13} />
            Interactive Visualizer
          </button>
          <button
            className={`btn btn-sm ${viewMode === 'figures' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('figures')}
            style={{ gap: '6px' }}
          >
            <LayoutGrid size={13} />
            300 DPI Figures (14)
          </button>
        </div>
      </div>

      {viewMode === 'interactive' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Row 1: Interactive Ingestion Velocity & 4-Tier Donut */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1fr', gap: '16px' }}>
            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: '13px', fontWeight: 600 }}>Event Ingestion Rate (1-Min Velocity Density)</span>
                <span className="badge badge-active">Dynamic SVG</span>
              </div>
              <div className="card-body">
                <InteractiveTimeline events={events} eda={eda} height={230} />
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: '13px', fontWeight: 600 }}>Audited 4-Tier Classification Donut</span>
                <span className="badge badge-active">Dynamic SVG</span>
              </div>
              <div className="card-body" style={{ display: 'flex', justifyContent: 'center' }}>
                <InteractiveTierDonut eda={eda} size={210} />
              </div>
            </div>
          </div>

          {/* Row 2: Interactive Principal Matrix */}
          <div className="card">
            <div className="card-header">
              <span style={{ fontSize: '13px', fontWeight: 600 }}>Sanitized Principal-to-Service Interaction Matrix (Heatmap)</span>
              <span className="badge badge-active">Interactive Matrix</span>
            </div>
            <div className="card-body">
              <InteractiveIdentityMatrix identities={identities} />
            </div>
          </div>

          {/* Row 3: Threat Emulation Runs Timeline & Services Bar Chart */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px' }}>
            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: '13px', fontWeight: 600 }}>Chronological Threat Run Execution (83 Runs)</span>
                <span className="badge badge-active">Live Timeline</span>
              </div>
              <div className="card-body">
                <InteractiveThreatTimeline runs={threatRuns} height={140} />
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <span style={{ fontSize: '13px', fontWeight: 600 }}>Top AWS Services & API Operations</span>
                <span className="badge badge-active">Interactive Bars</span>
              </div>
              <div className="card-body">
                <InteractiveServiceDistribution eda={eda} height={140} />
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Publication Gallery View */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Thematic Gallery Tabs */}
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '20px' }}>
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
                  securityTakeaway="300 errors (10.34%) observed, driven by intentional defense-evasion probing and throttling."
                />
                <FigureCard
                  figureNumber="Figure 08"
                  title="Top CloudTrail Error Codes"
                  imageSrc="/figures/eda/08_error_codes.png"
                  fieldsUsed={['error_code']}
                  calculationFormula="Value counts of error_code across all 300 error records."
                  securityTakeaway="ThrottlingException (102) and Client.UnauthorizedOperation (44) are the primary error triggers."
                />
              </>
            )}

            {tab === 'timeline' && (
              <>
                <FigureCard
                  figureNumber="Figure 12"
                  title="Hourly & Minute-Bin Event Volume"
                  imageSrc="/figures/eda/12_hourly_event_volume.png"
                  fieldsUsed={['timestamp']}
                  calculationFormula="1-minute time bin volume histogram over the 55-minute capture window."
                  securityTakeaway="Highlights temporal burst properties characteristic of automated attack automation."
                />
                <FigureCard
                  figureNumber="Figure 14"
                  title="Pure Detonation Activity Timeline by ATT&CK-Mapped Category"
                  imageSrc="/figures/eda/14_attack_timeline.png"
                  fieldsUsed={['timestamp', 'event_name', 'tier']}
                  calculationFormula="Chronological sequence of 214 pure detonation events annotated by MITRE ATT&CK tactic category."
                  securityTakeaway="Visualizes the temporal execution order across 83 test runs without implying a single continuous APT chain."
                />
              </>
            )}
          </div>
        </div>
      )}
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
          <h1>Comparative Baseline Benchmark Matrix</h1>
          <span className="page-description">
            Scientific multi-paradigm evaluation comparing Deterministic Rules (Baseline A), ML Anomaly Modeling (Baseline B), and Confidence-Aware Evidence Fusion (Proposed).
          </span>
        </div>
        <span className="badge badge-active">Research Benchmark</span>
      </div>

      {/* Benchmark Matrix Table */}
      <div className="card">
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600 }}>Multi-Baseline Comparative Performance</span>
        </div>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Detection Paradigm</th>
                <th>Model Architecture</th>
                <th>Trained Status</th>
                <th>Precision</th>
                <th>Event Recall (214)</th>
                <th>Technique Recall (83 Runs)</th>
                <th>False Positive Rate</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ background: '#f8fafc' }}>
                <td><strong style={{ color: '#0f172a' }}>Baseline A (Deterministic Rules)</strong></td>
                <td>Regex & Sigma Rule Engine</td>
                <td><span className="badge badge-active">Evaluated</span></td>
                <td style={{ fontWeight: 700, color: '#16a34a' }}>54.76% (23/42)</td>
                <td>2.01% (43/2,138)</td>
                <td style={{ fontWeight: 700, color: '#ca8a04' }}>20.48% (17/83)</td>
                <td>0.70% (19/2,686)</td>
              </tr>
              <tr>
                <td><strong>Baseline B (Unsupervised ML)</strong></td>
                <td>Isolation Forest + Autoencoder</td>
                <td><span className="badge badge-not-evaluated">Phase 4 Target</span></td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 4</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 4</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 4</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 4</td>
              </tr>
              <tr>
                <td><strong>Baseline C (Temporal Graph ML)</strong></td>
                <td>Temporal Graph Neural Network</td>
                <td><span className="badge badge-coming-soon">Phase 5 Target</span></td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 5</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 5</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 5</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 5</td>
              </tr>
              <tr style={{ background: '#faf5ff' }}>
                <td><strong style={{ color: '#9333ea' }}>Proposed: Multi-Source Evidence Fusion</strong></td>
                <td>Confidence-Aware Evidence Fusion</td>
                <td><span className="badge badge-coming-soon">Phase 6 Target</span></td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 6</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 6</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 6</td>
                <td style={{ color: '#94a3b8' }}>Pending Phase 6</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule Coverage Breakdown */}
      {baseline && baseline.findings_by_rule && (
        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Baseline A: Rule-by-Rule Detection Breakdown</span>
          </div>
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Detections Generated</th>
                  <th>Share of Baseline Findings</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(baseline.findings_by_rule).map(([ruleId, count]) => (
                  <tr key={ruleId}>
                    <td><code>{ruleId}</code></td>
                    <td style={{ fontWeight: 600, color: '#0f172a' }}>{count} alerts</td>
                    <td style={{ color: '#64748b' }}>
                      {((count / baseline.detection_summary.total_findings_generated) * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export const EvaluationProtocol: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Evaluation Methodology & Research Protocol</h1>
          <span className="page-description">
            Scientific definitions, metric calculations, and validation standards applied across the platform.
          </span>
        </div>
        <span className="badge badge-active">Peer-Review Standard</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>1. Precision & Recall Formulas</span>
          </div>
          <div className="card-body" style={{ fontSize: '12px', lineHeight: '1.6', color: '#334155' }}>
            <p><strong>Event-Level Precision:</strong></p>
            <code style={{ display: 'block', background: '#f8fafc', padding: '6px', margin: '4px 0 10px', borderRadius: '4px' }}>
              Precision = TP / (TP + FP) = 23 / 42 = 54.76%
            </code>
            <p><strong>Event-Level Recall (Tier 1 Pure Detonations):</strong></p>
            <code style={{ display: 'block', background: '#f8fafc', padding: '6px', margin: '4px 0 10px', borderRadius: '4px' }}>
              Event Recall = TP / 2,138 evaluated records = 2.01%
            </code>
            <p><strong>Technique Recall (83 Emulation Runs):</strong></p>
            <code style={{ display: 'block', background: '#f8fafc', padding: '6px', margin: '4px 0', borderRadius: '4px' }}>
              Technique Recall = Detected Runs / 83 = 17 / 83 = 20.48%
            </code>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>2. Experimental Reproducibility</span>
          </div>
          <div className="card-body" style={{ fontSize: '12px', lineHeight: '1.6', color: '#334155' }}>
            <p>All EDA figures and evaluation metrics are deterministically generated by:</p>
            <code style={{ display: 'block', background: '#0f172a', color: '#f8fafc', padding: '8px', margin: '6px 0 10px', borderRadius: '4px' }}>
              python experiments/generate_eda_figures.py
            </code>
            <p>The evaluation script validates all 14 figures against the exact 2,900 raw CloudTrail events with zero hardcoded assumptions.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

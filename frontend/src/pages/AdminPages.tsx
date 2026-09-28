import React from 'react';
import { StateBadge } from '../components/Badges';

export const TelemetryIntegrations: React.FC = () => {
  const connectors = [
    { name: 'AWS CloudTrail', status: 'Active', desc: '55 raw JSON logs ingested. 2,900 events evaluated.' },
    { name: 'AWS VPC Flow Logs', status: 'Not Connected', desc: 'Flow log stream connector via S3 / Athena.' },
    { name: 'AWS IAM Telemetry', status: 'Active', desc: 'Inferred principal state and policy attachment stream.' },
    { name: 'Amazon Inspector', status: 'Not Connected', desc: 'Host and container CVE vulnerability scanner feed.' },
    { name: 'AWS Config', status: 'Not Connected', desc: 'Configuration recorder and resource compliance evaluations.' },
    { name: 'Workload eBPF Probe', status: 'Coming Soon', desc: 'Host kernel-level process and network syscall monitor (Phase 7).' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Telemetry & Log Ingestion Integrations</h1>
          <span className="page-description">
            Status and configuration of cloud telemetry feeds connected to the ingestion engine.
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {connectors.map((c) => (
          <div key={c.name} className="card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontWeight: 700, fontSize: '14px', color: '#0f172a' }}>{c.name}</span>
              <StateBadge state={c.status as any} />
            </div>
            <p style={{ fontSize: '12px', color: '#64748b' }}>{c.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export const DetectionPolicies: React.FC = () => {
  const rules = [
    { id: 'RULE-IAM-001', name: 'AdministratorAccess Policy Attached', domain: 'IAM', sev: 'CRITICAL', status: 'Active' },
    { id: 'RULE-IAM-002', name: 'Inline IAM Policy Injected to User/Role', domain: 'IAM', sev: 'HIGH', status: 'Active' },
    { id: 'RULE-IAM-003', name: 'New IAM Access Key Created for Principal', domain: 'IAM', sev: 'HIGH', status: 'Active' },
    { id: 'RULE-CFG-001', name: 'CloudTrail Trail Logging Disabled / Deleted', domain: 'Configuration', sev: 'CRITICAL', status: 'Active' },
    { id: 'RULE-CFG-002', name: 'VPC Flow Logs Deleted / Disabled', domain: 'Configuration', sev: 'CRITICAL', status: 'Active' },
    { id: 'RULE-CFG-004', name: 'Secrets Manager Secret Deleted', domain: 'Configuration', sev: 'HIGH', status: 'Active' },
    { id: 'RULE-EXP-001', name: 'Security Group Ingress Opened to 0.0.0.0/0', domain: 'Exposure', sev: 'HIGH', status: 'Active' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Detection Policies & Rule Configuration</h1>
          <span className="page-description">
            Configured deterministic rules, severity mappings, and evaluation weights.
          </span>
        </div>
        <span className="badge badge-active">{rules.length} Active Rules</span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Rule Title</th>
              <th>Rule Domain</th>
              <th>Default Severity</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id}>
                <td><code>{r.id}</code></td>
                <td style={{ fontWeight: 600, color: '#0f172a' }}>{r.name}</td>
                <td>{r.domain}</td>
                <td><span className={`badge ${r.sev === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`}>{r.sev}</span></td>
                <td><span className="badge badge-active">Active</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const SystemSettings: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>System Configuration & Environment Variables</h1>
          <span className="page-description">
            Runtime environment configuration and safety thresholds.
          </span>
        </div>
      </div>

      <div className="card" style={{ padding: '16px' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>Operational Environment Parameters</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: '10px', fontSize: '13px' }}>
          <strong style={{ color: '#475569' }}>ENVIRONMENT:</strong>
          <code>research_lab</code>
          <strong style={{ color: '#475569' }}>DATASET_DIR:</strong>
          <code>data/raw/stratus_cloudtrail/CloudTrail</code>
          <strong style={{ color: '#475569' }}>RESPONSE_DRY_RUN:</strong>
          <code style={{ color: '#16a34a', fontWeight: 700 }}>true (Simulation Only)</code>
          <strong style={{ color: '#475569' }}>RULE_ENGINE_VERSION:</strong>
          <code>1.0.0 (Baseline A)</code>
          <strong style={{ color: '#475569' }}>ML_ENGINE_STATUS:</strong>
          <code>Phase 4 Target (Unsupervised Isolation Forest)</code>
        </div>
      </div>
    </div>
  );
};

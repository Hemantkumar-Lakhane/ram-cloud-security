import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { SecurityFinding, EDASummary, BaselineMetrics } from '../types';
import { SeverityBadge } from '../components/Badges';
import { Shield, Activity, Users, Layers, ExternalLink } from 'lucide-react';

export const SecurityOverview: React.FC<{
  onSelectFinding: (finding: SecurityFinding) => void;
  onNavigate: (route: string) => void;
}> = ({ onSelectFinding, onNavigate }) => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [eda, setEDA] = useState<EDASummary | null>(null);
  const [baseline, setBaseline] = useState<BaselineMetrics | null>(null);

  useEffect(() => {
    dataService.getFindings().then(setFindings);
    dataService.getEDASummary().then(setEDA);
    dataService.getBaselineMetrics().then(setBaseline);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-title-group">
          <h1>Security Posture Overview</h1>
          <span className="page-description">
            Live telemetry dynamics, deterministic rule detections, and posture state across the monitored AWS environment.
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('/research/eda')}>
            View All 14 EDA Figures
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => onNavigate('/security/findings')}>
            Triage 42 Findings
          </button>
        </div>
      </div>

      {/* Zone 1: Restrained Status Strip (Anti-Slop Compact Single Strip) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '12px',
        background: '#ffffff',
        padding: '16px',
        borderRadius: '4px',
        border: '1px solid #e5e7eb',
        boxShadow: '0 1px 2px rgba(0,0,0,0.03)'
      }}>
        <div style={{ borderRight: '1px solid #f1f5f9', paddingRight: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
            <Activity size={13} color="#2563eb" /> Telemetry Evaluated
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.total_records.toLocaleString() : '2,900'} <span style={{ fontSize: '12px', fontWeight: 400, color: '#64748b' }}>Events</span>
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>Window: {eda ? eda.time_span.duration_minutes : '55.5'} mins (CloudTrail)</span>
        </div>

        <div style={{ borderRight: '1px solid #f1f5f9', paddingRight: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
            <Shield size={13} color="#dc2626" /> Active Rule Findings
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#dc2626', marginTop: '4px' }}>
            {baseline ? baseline.detection_summary.total_findings_generated : '42'} <span style={{ fontSize: '12px', fontWeight: 400, color: '#64748b' }}>Alerts</span>
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>15 Critical | 25 High | 2 Medium</span>
        </div>

        <div style={{ borderRight: '1px solid #f1f5f9', paddingRight: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
            <Users size={13} color="#ea580c" /> Active IAM Principals
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.distinct_counts.actors : '14'} <span style={{ fontSize: '12px', fontWeight: 400, color: '#64748b' }}>Identities</span>
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>2 Users | 10 Roles | 2 Services</span>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
            <Layers size={13} color="#475569" /> Monitored AWS Services
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', marginTop: '4px' }}>
            {eda ? eda.distinct_counts.services : '29'} <span style={{ fontSize: '12px', fontWeight: 400, color: '#64748b' }}>Services</span>
          </div>
          <span style={{ fontSize: '11px', color: '#94a3b8' }}>Top: EC2, SSM, IAM, S3, KMS</span>
        </div>
      </div>

      {/* Zone 2: Telemetry Dynamics (Figure 09 & Figure 01) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '16px' }}>
        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Event Ingestion Rate (1-Min Velocity Density)</span>
            <span className="badge badge-info">Figure 09</span>
          </div>
          <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
            <img
              src="/figures/eda/09_event_timeline.png"
              alt="Figure 09"
              style={{ maxWidth: '100%', height: '230px', objectFit: 'contain', background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
            />
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Operational Activity Tier Breakdown</span>
            <span className="badge badge-info">Figure 01</span>
          </div>
          <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
            <img
              src="/figures/eda/01_dataset_activity_distribution.png"
              alt="Figure 01"
              style={{ maxWidth: '100%', height: '230px', objectFit: 'contain', background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
            />
          </div>
        </div>
      </div>

      {/* Zone 3: Priority Findings Live Triage Table */}
      <div className="card">
        <div className="card-header">
          <div>
            <span style={{ fontSize: '13px', fontWeight: 600 }}>High-Priority Security Alerts</span>
            <span style={{ fontSize: '12px', color: '#64748b', marginLeft: '8px' }}>
              Showing top unhandled detections from Deterministic Baseline A
            </span>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('/security/findings')}>
            View All ({findings.length}) <ExternalLink size={12} />
          </button>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding ID & Title</th>
                <th>Rule Engine</th>
                <th>Actor Identity</th>
                <th>Resource ARN</th>
                <th>Event Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 7).map((f) => (
                <tr key={f.finding_id} className="clickable" onClick={() => onSelectFinding(f)}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                  <td><code>{f.rule_id}</code></td>
                  <td><code>{f.sanitized_actor}</code></td>
                  <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <code>{f.resource_id}</code>
                  </td>
                  <td style={{ fontSize: '12px', color: '#64748b' }}>{f.timestamp.replace('T', ' ').substring(0, 19)}</td>
                  <td>
                    <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); onSelectFinding(f); }}>
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

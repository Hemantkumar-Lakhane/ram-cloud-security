import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { SecurityFinding } from '../types';
import { SeverityBadge } from '../components/Badges';
import { RefreshCw, Lock } from 'lucide-react';

export const ResponseCenter: React.FC<{
  onOpenResponseModal: (finding: SecurityFinding) => void;
}> = ({ onOpenResponseModal }) => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);

  useEffect(() => {
    dataService.getFindings().then(setFindings);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Safe Response Center (Policy-Gated)</h1>
          <span className="page-description">
            Human-in-the-loop automated response queue with strict simulation defaults and dry-run safety locks.
          </span>
        </div>
        <span className="badge badge-active">DRY_RUN = True Mode</span>
      </div>

      {/* Tri-State Safety Gating Banner */}
      <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', padding: '14px 18px', borderRadius: '4px', fontSize: '12px', color: '#1e40af', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Lock size={16} />
          <div>
            <strong>Operational Tri-State Model:</strong> Recommendation (Available) $\to$ Dry Run Simulation (Active) $\to$ Live Remediation (Disabled/Safety Lock).
          </div>
        </div>
        <span className="badge badge-active">Simulation Engine Ready</span>
      </div>

      <div className="card">
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600 }}>Remediation Recommendation Queue</span>
          <span style={{ fontSize: '12px', color: '#64748b' }}>{findings.length} Actionable Playbooks</span>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert Title</th>
                <th>Target Cloud Resource</th>
                <th>Recommended Playbook</th>
                <th>Action Command</th>
                <th>Safety Mode</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 10).map((f) => (
                <tr key={f.finding_id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                  <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <code>{f.resource_id}</code>
                  </td>
                  <td>{f.recommended_action.playbook}</td>
                  <td><code>{f.recommended_action.action_name}</code></td>
                  <td><span className="badge badge-active" style={{ fontSize: '10px' }}>Dry Run Gated</span></td>
                  <td>
                    <button className="btn btn-primary btn-sm" onClick={() => onOpenResponseModal(f)}>
                      <RefreshCw size={12} /> Preview
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

export const ActionHistory: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Response Action Audit History</h1>
          <span className="page-description">
            Immutable log of executed dry-run simulations and authorized remediation playbooks.
          </span>
        </div>
        <span className="badge badge-active">Audit Logging Live</span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Action ID</th>
              <th>Target Resource</th>
              <th>Remediation Action</th>
              <th>Authorized By</th>
              <th>Execution Mode</th>
              <th>Outcome</th>
              <th>Timestamp (UTC)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>ACT-20230710-001</code></td>
              <td><code>arn:aws:cloudtrail:us-east-1:123456789012:trail/GlobalTrail</code></td>
              <td><code>aws:cloudtrail:StartLogging</code></td>
              <td><code>SecurityAnalyst-01</code></td>
              <td><span className="badge badge-active">DRY_RUN (Simulated)</span></td>
              <td><span style={{ color: '#16a34a', fontWeight: 600 }}>SIMULATED_SUCCESS</span></td>
              <td style={{ fontSize: '12px', color: '#64748b' }}>2023-07-10 12:20:15</td>
            </tr>
            <tr>
              <td><code>ACT-20230710-002</code></td>
              <td><code>arn:aws:iam::123456789012:user/IAMUser-01</code></td>
              <td><code>aws:iam:DeactivateAccessKey</code></td>
              <td><code>SecurityAnalyst-01</code></td>
              <td><span className="badge badge-active">DRY_RUN (Simulated)</span></td>
              <td><span style={{ color: '#16a34a', fontWeight: 600 }}>SIMULATED_SUCCESS</span></td>
              <td style={{ fontSize: '12px', color: '#64748b' }}>2023-07-10 12:24:08</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

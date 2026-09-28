import React, { useState } from 'react';
import { X, ShieldAlert, FileText, Layers, RefreshCw } from 'lucide-react';
import type { SecurityFinding } from '../types';
import { SeverityBadge, StateBadge } from './Badges';

export const DetailDrawer: React.FC<{
  finding: SecurityFinding | null;
  onClose: () => void;
  onOpenResponseModal: (finding: SecurityFinding) => void;
}> = ({ finding, onClose, onOpenResponseModal }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'raw_json'>('overview');

  if (!finding) return null;

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <SeverityBadge severity={finding.severity} />
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#4b5563' }}>{finding.finding_id}</span>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="tabs-nav" style={{ padding: '0 20px' }}>
          <button className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
            Forensic Overview
          </button>
          <button className={`tab-button ${activeTab === 'evidence' ? 'active' : ''}`} onClick={() => setActiveTab('evidence')}>
            Evidence Sources
          </button>
          <button className={`tab-button ${activeTab === 'raw_json' ? 'active' : ''}`} onClick={() => setActiveTab('raw_json')}>
            Normalized Payload
          </button>
        </div>

        <div className="drawer-body">
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>{finding.title}</h2>
                <p style={{ fontSize: '13px', color: '#4b5563', lineHeight: '1.5' }}>{finding.description}</p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: '#f8fafc', padding: '12px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
                <div>
                  <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Actor Identity</span>
                  <div style={{ fontWeight: 600, fontSize: '13px', color: '#0f172a' }}>{finding.sanitized_actor}</div>
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>Type: {finding.actor_type}</span>
                </div>
                <div>
                  <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Confidence Score</span>
                  <div style={{ fontWeight: 600, fontSize: '13px', color: '#0f172a' }}>{finding.confidence.toFixed(2)} (Deterministic)</div>
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>Source: {finding.rule_id}</span>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Affected Cloud Resource</span>
                <div style={{ fontSize: '12px', fontFamily: 'monospace', background: '#f1f5f9', padding: '6px 10px', borderRadius: '4px', marginTop: '4px', wordBreak: 'break-all' }}>
                  {finding.resource_id}
                </div>
              </div>

              <div style={{ border: '1px solid #e2e8f0', borderRadius: '4px', padding: '12px', background: '#ffffff' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: '#1e293b' }}>Recommended Remediation</span>
                  <span className="badge badge-active" style={{ fontSize: '10px' }}>Dry Run Gated</span>
                </div>
                <p style={{ fontSize: '12px', color: '#475569', marginBottom: '10px' }}>{finding.recommended_action.playbook}</p>
                <button
                  className="btn btn-primary btn-sm"
                  style={{ width: '100%', justifyContent: 'center' }}
                  onClick={() => onOpenResponseModal(finding)}
                >
                  <RefreshCw size={14} /> Preview Remediation [Dry Run]
                </button>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ border: '1px solid #e2e8f0', borderRadius: '4px', padding: '12px', background: '#f8fafc' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldAlert size={14} color="#2563eb" /> Rule Evidence
                  </span>
                  <StateBadge state="Active" />
                </div>
                <pre style={{ background: '#ffffff', padding: '10px', borderRadius: '4px', border: '1px solid #cbd5e1', overflowX: 'auto' }}>
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </div>

              <div style={{ border: '1px solid #e2e8f0', borderRadius: '4px', padding: '12px', background: '#f8fafc' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Layers size={14} color="#64748b" /> Statistical Anomaly Evidence
                  </span>
                  <StateBadge state="Not Evaluated" />
                </div>
                <p style={{ fontSize: '12px', color: '#64748b' }}>
                  Unsupervised Isolation Forest / Autoencoder anomaly scoring will be evaluated in Phase 4.
                </p>
              </div>

              <div style={{ border: '1px solid #e2e8f0', borderRadius: '4px', padding: '12px', background: '#f8fafc' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileText size={14} color="#64748b" /> Behavioral Sequence Evidence
                  </span>
                  <StateBadge state="Not Evaluated" />
                </div>
                <p style={{ fontSize: '12px', color: '#64748b' }}>
                  Temporal Graph Neural Network progression scoring will be evaluated in Phase 5.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'raw_json' && (
            <div>
              <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '14px', borderRadius: '6px', fontSize: '11px', overflowX: 'auto' }}>
                {JSON.stringify(finding, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const ActionModal: React.FC<{
  finding: SecurityFinding | null;
  isOpen: boolean;
  onClose: () => void;
}> = ({ finding, isOpen, onClose }) => {
  const [justification, setJustification] = useState('');
  const [simulated, setSimulated] = useState(false);

  if (!isOpen || !finding) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{ fontSize: '15px', fontWeight: 700 }}>Human Authorization & Remediation Gate</h3>
          <button className="btn btn-secondary btn-sm" onClick={onClose}><X size={14} /></button>
        </div>

        <div className="modal-body">
          <div style={{ background: '#fffbeb', border: '1px solid #fde68a', padding: '10px 12px', borderRadius: '4px', fontSize: '12px', color: '#92400e', fontWeight: 600 }}>
            SAFETY LOCK ENGAGED — DRY RUN MODE (Simulation Only)
          </div>

          <div>
            <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Target Resource</span>
            <div style={{ fontSize: '12px', fontFamily: 'monospace', background: '#f1f5f9', padding: '6px 8px', borderRadius: '4px', marginTop: '4px' }}>
              {finding.resource_id}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>Action Command</span>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1e293b', marginTop: '2px' }}>
              <code>{finding.recommended_action.action_name}</code>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
            <div style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: '8px', borderRadius: '4px' }}>
              <strong>Before State:</strong><br />
              <code>logging_status: Disabled</code>
            </div>
            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '8px', borderRadius: '4px' }}>
              <strong>Expected After State:</strong><br />
              <code>logging_status: Enabled</code>
            </div>
          </div>

          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: '#334155', display: 'block', marginBottom: '4px' }}>
              Mandatory Audit Justification:
            </label>
            <textarea
              style={{ width: '100%', height: '60px', padding: '8px', border: '1px solid #cbd5e1', borderRadius: '4px', fontSize: '12px', fontFamily: 'inherit' }}
              placeholder="e.g., Authorized containment for StopLogging event by IAMUser-01..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
            />
          </div>

          {simulated && (
            <div style={{ background: '#f0fdf4', border: '1px solid #86efac', padding: '8px 12px', borderRadius: '4px', fontSize: '12px', color: '#166534' }}>
              [SIMULATION SUCCESS] Dry-run action logged to audit store. Zero cloud state mutated.
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            disabled={!justification.trim() || simulated}
            onClick={() => setSimulated(true)}
          >
            Confirm & Simulate Response [Dry Run]
          </button>
        </div>
      </div>
    </div>
  );
};

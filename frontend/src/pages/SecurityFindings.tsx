import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { SecurityFinding, SeverityLevel } from '../types';
import { SeverityBadge } from '../components/Badges';
import { Search, Filter, Eye } from 'lucide-react';

export const SecurityFindings: React.FC<{
  onSelectFinding: (finding: SecurityFinding) => void;
}> = ({ onSelectFinding }) => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedRule, setSelectedRule] = useState<string>('ALL');

  useEffect(() => {
    dataService.getFindings().then(setFindings);
  }, []);

  const filtered = findings.filter(f => {
    const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          f.sanitized_actor.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          f.resource_id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    const matchesRule = selectedRule === 'ALL' || f.rule_id.startsWith(selectedRule);
    return matchesSearch && matchesSeverity && matchesRule;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Security Findings Inventory</h1>
          <span className="page-description">
            Filter, search, and triage all security alerts generated across the telemetry stream by the Deterministic Rule Engine.
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="badge badge-active">42 Total Detections</span>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', background: '#ffffff', padding: '12px 16px', borderRadius: '4px', border: '1px solid #e5e7eb', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#f8fafc', padding: '4px 10px', borderRadius: '4px', border: '1px solid #cbd5e1', flex: 1, minWidth: '220px' }}>
          <Search size={14} color="#64748b" />
          <input
            type="text"
            placeholder="Search findings, actors, resources..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '13px', width: '100%' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Filter size={14} color="#64748b" />
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', fontSize: '12px', background: '#ffffff' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>

          <select
            value={selectedRule}
            onChange={(e) => setSelectedRule(e.target.value)}
            style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', fontSize: '12px', background: '#ffffff' }}
          >
            <option value="ALL">All Detection Rules</option>
            <option value="RULE-CFG">Configuration Rules (CFG)</option>
            <option value="RULE-IAM">IAM Rules (IAM)</option>
            <option value="RULE-EXP">Exposure Rules (EXP)</option>
          </select>
        </div>
      </div>

      {/* Findings Data Table */}
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding Title</th>
              <th>Detection Rule</th>
              <th>Actor Identity</th>
              <th>Target Resource</th>
              <th>Timestamp (UTC)</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.finding_id} className="clickable" onClick={() => onSelectFinding(f)}>
                <td><SeverityBadge severity={f.severity as SeverityLevel} /></td>
                <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                <td><code>{f.rule_id}</code></td>
                <td><code>{f.sanitized_actor}</code></td>
                <td style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <code>{f.resource_id}</code>
                </td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{f.timestamp.replace('T', ' ').substring(0, 19)}</td>
                <td><span className="badge badge-info">{f.confidence.toFixed(2)}</span></td>
                <td><span className="badge badge-high" style={{ fontSize: '10px' }}>{f.status}</span></td>
                <td>
                  <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); onSelectFinding(f); }}>
                    <Eye size={12} /> Inspect
                  </button>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '32px', color: '#94a3b8' }}>
                  No security findings match your filter criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

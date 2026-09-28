import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { TelemetryEvent, ThreatRun } from '../types';
import { ProvenancePill } from '../components/Badges';
import { Search } from 'lucide-react';

export const TelemetryExplorer: React.FC = () => {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');
  const [expandedEvent, setExpandedEvent] = useState<TelemetryEvent | null>(null);

  useEffect(() => {
    dataService.getEvents().then(setEvents);
  }, []);

  const filtered = events.filter(e => {
    const matchesSearch = e.event_name.toLowerCase().includes(search.toLowerCase()) ||
                          e.sanitized_actor.toLowerCase().includes(search.toLowerCase()) ||
                          e.event_source.toLowerCase().includes(search.toLowerCase());
    const matchesTier = tierFilter === 'ALL' || e.tier.includes(tierFilter);
    return matchesSearch && matchesTier;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Event Telemetry Explorer</h1>
          <span className="page-description">
            Stream explorer for normalized AWS CloudTrail records with progressive disclosure of raw parameters.
          </span>
        </div>
        <span className="badge badge-active">2,900 Records Ingested</span>
      </div>

      <div style={{ display: 'flex', gap: '12px', background: '#ffffff', padding: '12px', borderRadius: '4px', border: '1px solid #e5e7eb' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#f8fafc', padding: '4px 10px', borderRadius: '4px', border: '1px solid #cbd5e1', flex: 1 }}>
          <Search size={14} color="#64748b" />
          <input
            type="text"
            placeholder="Search API name, actor, service..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '13px', width: '100%' }}
          />
        </div>

        <select
          value={tierFilter}
          onChange={(e) => setTierFilter(e.target.value)}
          style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', fontSize: '12px', background: '#ffffff' }}
        >
          <option value="ALL">All Operational Tiers</option>
          <option value="Pure Detonation">Tier 1: Pure Detonation (214)</option>
          <option value="Warmup">Tier 2: Warmup/Cleanup (932)</option>
          <option value="Operator">Tier 3: Operator TF (1006)</option>
          <option value="Background">Tier 4: AWS Background (748)</option>
        </select>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>API Action (Event Name)</th>
              <th>AWS Service</th>
              <th>Sanitized Actor</th>
              <th>Source IP</th>
              <th>Operational Provenance</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 20).map((e) => (
              <tr key={e.event_id} className="clickable" onClick={() => setExpandedEvent(expandedEvent?.event_id === e.event_id ? null : e)}>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{e.timestamp.replace('T', ' ').substring(0, 19)}</td>
                <td style={{ fontWeight: 600, color: '#0f172a' }}><code>{e.event_name}</code></td>
                <td><code>{e.event_source}</code></td>
                <td><code>{e.sanitized_actor}</code></td>
                <td style={{ fontSize: '12px' }}>{e.source_ip}</td>
                <td><ProvenancePill tier={e.tier} /></td>
                <td>
                  {e.is_error ? (
                    <span className="badge badge-high" style={{ fontSize: '10px' }}>{e.error_code || 'Error'}</span>
                  ) : (
                    <span className="badge badge-active" style={{ fontSize: '10px' }}>Success</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {expandedEvent && (
        <div className="card" style={{ marginTop: '8px' }}>
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Event Inspector: {expandedEvent.event_id}</span>
            <button className="btn btn-secondary btn-sm" onClick={() => setExpandedEvent(null)}>Close</button>
          </div>
          <div className="card-body">
            <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '12px', borderRadius: '4px', fontSize: '11px', overflowX: 'auto' }}>
              {JSON.stringify(expandedEvent, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export const ThreatActivity: React.FC = () => {
  const [runs, setRuns] = useState<ThreatRun[]>([]);

  useEffect(() => {
    dataService.getThreatRuns().then(setRuns);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Threat Activity & Emulation Runs</h1>
          <span className="page-description">
            Inventory of 83 discrete Stratus Red Team detonation runs evaluated across the telemetry capture.
          </span>
        </div>
        <span className="badge badge-active">83 Distinct Emulation Runs</span>
      </div>

      <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', padding: '12px 16px', borderRadius: '4px', fontSize: '12px', color: '#475569' }}>
        <strong>Coverage Summary:</strong> 17 runs detected by Baseline A Rules (20.48% technique recall); 66 runs undetected due to discovery/stealth APIs (providing the empirical motivation for Phase 4 ML Anomaly Modeling).
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Detonation UUID Tag</th>
              <th>Event Count</th>
              <th>Targeted Services</th>
              <th>Adversarial APIs Sample</th>
              <th>First Executed (UTC)</th>
              <th>Rule Baseline A Coverage</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.detonation_uuid}>
                <td style={{ fontWeight: 600, color: '#0f172a' }}><code>{r.detonation_uuid}</code></td>
                <td>{r.event_count} calls</td>
                <td>{r.services.join(', ')}</td>
                <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.apis.join(', ')}
                </td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{r.first_seen.replace('T', ' ').substring(11, 19)}</td>
                <td>
                  {r.detected_by_baseline_a ? (
                    <span className="badge badge-active" style={{ fontSize: '10px' }}>Detected ({r.findings_count} Alerts)</span>
                  ) : (
                    <span className="badge badge-not-evaluated" style={{ fontSize: '10px' }}>Missed by Rules</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

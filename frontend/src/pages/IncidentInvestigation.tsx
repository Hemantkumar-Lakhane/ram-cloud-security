import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { IdentityRecord, TelemetryEvent } from '../types';
import { ProvenancePill } from '../components/Badges';
import { Info } from 'lucide-react';

export const IncidentInvestigation: React.FC = () => {
  const [identities, setIdentities] = useState<IdentityRecord[]>([]);
  const [selectedActor, setSelectedActor] = useState<string>('IAMUser-01');
  const [events, setEvents] = useState<TelemetryEvent[]>([]);

  useEffect(() => {
    dataService.getIdentities().then(setIdentities);
    dataService.getEvents().then(setEvents);
  }, []);

  const actorEvents = events.filter(e => e.sanitized_actor === selectedActor);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Incident Investigation Workspace</h1>
          <span className="page-description">
            Multi-signal temporal correlation linking IAM actors, targeted services, and observed emulation timelines.
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <label style={{ fontSize: '12px', fontWeight: 600, color: '#475569' }}>Focus Principal:</label>
          <select
            value={selectedActor}
            onChange={(e) => setSelectedActor(e.target.value)}
            style={{ padding: '4px 10px', borderRadius: '4px', border: '1px solid #cbd5e1', fontSize: '12px', background: '#ffffff', fontWeight: 600 }}
          >
            {identities.map(i => (
              <option key={i.sanitized_id} value={i.sanitized_id}>
                {i.sanitized_id} ({i.total_events} evts) — {i.actor_type}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Disambiguation Disclaimer Box */}
      <div style={{ background: '#fefce8', border: '1px solid #fef08a', padding: '12px 16px', borderRadius: '4px', fontSize: '12px', color: '#854d0e', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
        <Info size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong>Investigation Methodology Note:</strong> Telemetry reflects discrete, independent Stratus Red Team adversary emulation runs executed sequentially across the capture. Chronological sequence represents execution order across distinct tests and does not establish a single coordinated APT campaign.
        </div>
      </div>

      {/* Visual Investigation Canvas (Figure 14 & Figure 12) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px' }}>
        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Pure Detonation Activity Timeline by ATT&CK Category</span>
            <span className="badge badge-info">Figure 14</span>
          </div>
          <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
            <img
              src="/figures/eda/14_attack_sequence_timeline.png"
              alt="Figure 14"
              style={{ maxWidth: '100%', height: '240px', objectFit: 'contain', background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
            />
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Cross-Service Temporal Activity Intensity</span>
            <span className="badge badge-info">Figure 12</span>
          </div>
          <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
            <img
              src="/figures/eda/12_service_activity_heatmap.png"
              alt="Figure 12"
              style={{ maxWidth: '100%', height: '240px', objectFit: 'contain', background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
            />
          </div>
        </div>
      </div>

      {/* Synchronized Observed Event Stream for Selected Actor */}
      <div className="card">
        <div className="card-header">
          <div>
            <span style={{ fontSize: '13px', fontWeight: 600 }}>Observed Telemetry Stream for {selectedActor}</span>
            <span style={{ fontSize: '12px', color: '#64748b', marginLeft: '8px' }}>
              Showing {actorEvents.length} events in local window
            </span>
          </div>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Event Name (API)</th>
                <th>AWS Service</th>
                <th>Source IP</th>
                <th>Operational Tier</th>
                <th>Execution Result</th>
              </tr>
            </thead>
            <tbody>
              {actorEvents.slice(0, 10).map((e) => (
                <tr key={e.event_id}>
                  <td style={{ fontSize: '12px', color: '#64748b' }}>{e.timestamp.replace('T', ' ').substring(0, 19)}</td>
                  <td style={{ fontWeight: 600, color: '#0f172a' }}><code>{e.event_name}</code></td>
                  <td><code>{e.event_source}</code></td>
                  <td style={{ fontSize: '12px', color: '#475569' }}>{e.source_ip}</td>
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
      </div>
    </div>
  );
};

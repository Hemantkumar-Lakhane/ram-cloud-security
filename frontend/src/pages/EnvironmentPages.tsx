import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { AssetRecord, IdentityRecord } from '../types';
import { FutureStateBanner } from '../components/Badges';

export const AssetsInventory: React.FC = () => {
  const [assets, setAssets] = useState<AssetRecord[]>([]);

  useEffect(() => {
    dataService.getAssets().then(setAssets);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Cloud Assets Inventory</h1>
          <span className="page-description">
            Discovered AWS cloud resources touched by observed CloudTrail telemetry and associated security findings.
          </span>
        </div>
        <span className="badge badge-active">{assets.length} Resources Tracked</span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Resource Identifier / ARN</th>
              <th>AWS Service</th>
              <th>Region</th>
              <th>Event Volume</th>
              <th>Associated Findings</th>
              <th>Risk Level</th>
              <th>Last Touched</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.resource_id}>
                <td style={{ fontWeight: 600, color: '#0f172a', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <code>{a.resource_id}</code>
                </td>
                <td><code>{a.service}</code></td>
                <td>{a.region}</td>
                <td>{a.event_count} calls</td>
                <td>
                  {a.findings_count > 0 ? (
                    <span className="badge badge-critical">{a.findings_count} Alerts</span>
                  ) : (
                    <span style={{ fontSize: '12px', color: '#94a3b8' }}>0</span>
                  )}
                </td>
                <td>
                  <span className={`badge ${a.risk_level === 'CRITICAL' ? 'badge-critical' : (a.risk_level === 'HIGH' ? 'badge-high' : 'badge-info')}`}>
                    {a.risk_level}
                  </span>
                </td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{a.last_seen.replace('T', ' ').substring(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const IdentitiesMonitor: React.FC = () => {
  const [identities, setIdentities] = useState<IdentityRecord[]>([]);

  useEffect(() => {
    dataService.getIdentities().then(setIdentities);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Identities & IAM Principal Monitor</h1>
          <span className="page-description">
            Sanitized principal activity profiles, service access footprints, and behavioral baselines.
          </span>
        </div>
        <span className="badge badge-active">14 Sanitized Principals</span>
      </div>

      {/* Embedded Figure 13 (Principal-to-Service Matrix) */}
      <div className="card">
        <div className="card-header">
          <span style={{ fontSize: '13px', fontWeight: 600 }}>Principal-to-Service Interaction Matrix (Raw Counts vs Access Profile %)</span>
          <span className="badge badge-info">Figure 13 (Dual-Panel)</span>
        </div>
        <div style={{ padding: '12px', background: '#f8fafc', display: 'flex', justifyContent: 'center' }}>
          <img
            src="/figures/eda/13_identity_service_relationship.png"
            alt="Figure 13"
            style={{ maxWidth: '100%', height: '260px', objectFit: 'contain', background: '#ffffff', borderRadius: '4px', border: '1px solid #e2e8f0' }}
          />
        </div>
      </div>

      {/* Identities Table */}
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Sanitized Principal ID</th>
              <th>Actor Type</th>
              <th>Total Events</th>
              <th>Error Count</th>
              <th>Services Accessed</th>
              <th>Findings Triggered</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {identities.map((id) => (
              <tr key={id.sanitized_id}>
                <td style={{ fontWeight: 700, color: '#0f172a' }}><code>{id.sanitized_id}</code></td>
                <td><span className="badge badge-info">{id.actor_type}</span></td>
                <td style={{ fontWeight: 600 }}>{id.total_events.toLocaleString()}</td>
                <td>
                  {id.error_count > 0 ? (
                    <span style={{ color: '#dc2626', fontWeight: 600 }}>{id.error_count}</span>
                  ) : (
                    <span style={{ color: '#16a34a' }}>0</span>
                  )}
                </td>
                <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {id.services.join(', ')}
                </td>
                <td>
                  {id.findings_count > 0 ? (
                    <span className="badge badge-critical">{id.findings_count} Alerts</span>
                  ) : (
                    <span style={{ color: '#94a3b8' }}>0</span>
                  )}
                </td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{id.first_seen.replace('T', ' ').substring(11, 19)}</td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{id.last_seen.replace('T', ' ').substring(11, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const WorkloadRuntime: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Workload & Container Runtimes</h1>
          <span className="page-description">
            Runtime security, kernel syscall probes, and container anomalous execution monitoring.
          </span>
        </div>
        <span className="badge badge-coming-soon">Phase 7 Roadmap</span>
      </div>

      <FutureStateBanner
        title="Workload eBPF Runtime Security Module"
        phase="Phase 7 Implementation Target"
        description="Container runtime anomaly detection and host kernel probe monitoring will be implemented in Phase 7. The current system focuses on cloud-plane CloudTrail telemetry."
        requiredInput="Linux eBPF kernel daemon, kprobe/tracepoint ringbuffer telemetry, Kubernetes pod metadata stream."
      />
    </div>
  );
};

export const NetworkTopology: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Network Topology & VPCs</h1>
          <span className="page-description">
            VPC flow analysis, lateral movement detection, and ingress/egress network exposure maps.
          </span>
        </div>
        <span className="badge badge-coming-soon">Future Ingestion</span>
      </div>

      <FutureStateBanner
        title="VPC Flow Logs & Network Correlation Engine"
        phase="Network Ingestion Module"
        description="Network traffic flow log ingestion and cross-VPC flow graph correlation will be activated once the AWS S3 VPC Flow Log connector is enabled in Administration."
        requiredInput="Amazon VPC Flow Logs in Parquet/JSON format, Security Group egress/ingress state mapping."
      />
    </div>
  );
};

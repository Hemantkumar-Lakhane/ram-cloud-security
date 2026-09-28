import React, { useEffect, useState } from 'react';
import { dataService } from '../services/dataService';
import type { SecurityFinding } from '../types';
import { SeverityBadge, FutureStateBanner } from '../components/Badges';

export const Misconfigurations: React.FC<{
  onSelectFinding: (finding: SecurityFinding) => void;
}> = ({ onSelectFinding }) => {
  const [cfgFindings, setCfgFindings] = useState<SecurityFinding[]>([]);

  useEffect(() => {
    dataService.getFindings().then(findings => {
      setCfgFindings(findings.filter(f => f.rule_id.startsWith('RULE-CFG')));
    });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Cloud Misconfigurations</h1>
          <span className="page-description">
            Audit of active cloud configuration drift, resource policy deviations, and security trail modifications.
          </span>
        </div>
        <span className="badge badge-critical">{cfgFindings.length} Active Deviations</span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Misconfiguration Title</th>
              <th>Resource ARN</th>
              <th>Responsible Actor</th>
              <th>Detected Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {cfgFindings.map((f) => (
              <tr key={f.finding_id} className="clickable" onClick={() => onSelectFinding(f)}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><code>{f.rule_id}</code></td>
                <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                <td style={{ maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <code>{f.resource_id}</code>
                </td>
                <td><code>{f.sanitized_actor}</code></td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{f.timestamp.replace('T', ' ').substring(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const Vulnerabilities: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Vulnerabilities & CVEs</h1>
          <span className="page-description">
            Host CVE scans, container package vulnerabilities, and Common Weakness Enumerations.
          </span>
        </div>
        <span className="badge badge-not-connected">Not Connected</span>
      </div>

      <FutureStateBanner
        title="Vulnerability Scanning Connector"
        phase="Integration Target"
        description="Amazon Inspector / Trivy vulnerability feed is not connected to this workspace. Ingestion of CVE findings is disabled."
        requiredInput="AWS Inspector v2 EventBridge stream or automated CycloneDX SBOM vulnerability reports."
      />
    </div>
  );
};

export const ComplianceFrameworks: React.FC = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Compliance Frameworks (CIS AWS Benchmark)</h1>
          <span className="page-description">
            Continuous compliance evaluation against CIS AWS Foundations Benchmark v1.4.0 and NIST 800-53.
          </span>
        </div>
        <span className="badge badge-coming-soon">Roadmap Target</span>
      </div>

      <FutureStateBanner
        title="CIS AWS Foundations Compliance Engine"
        phase="Compliance Module Target"
        description="Automated mapping of deterministic rules and posture findings to CIS benchmark controls is scheduled for future release."
        requiredInput="AWS Config evaluated rules and IAM credential report exports."
      />
    </div>
  );
};

export const AttackSurfaceExposure: React.FC<{
  onSelectFinding: (finding: SecurityFinding) => void;
}> = ({ onSelectFinding }) => {
  const [expFindings, setExpFindings] = useState<SecurityFinding[]>([]);

  useEffect(() => {
    dataService.getFindings().then(findings => {
      setExpFindings(findings.filter(f => f.rule_id.startsWith('RULE-EXP')));
    });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="page-header">
        <div className="page-title-group">
          <h1>Attack Surface Exposure</h1>
          <span className="page-description">
            Monitoring public IP exposures, open Security Group ingress rules (0.0.0.0/0), and unrestricted bucket policies.
          </span>
        </div>
        <span className="badge badge-high">{expFindings.length} Exposure Alerts</span>
      </div>

      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Exposure Finding</th>
              <th>Resource</th>
              <th>Actor</th>
              <th>Detected Time</th>
            </tr>
          </thead>
          <tbody>
            {expFindings.map((f) => (
              <tr key={f.finding_id} className="clickable" onClick={() => onSelectFinding(f)}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><code>{f.rule_id}</code></td>
                <td style={{ fontWeight: 600, color: '#0f172a' }}>{f.title}</td>
                <td><code>{f.resource_id}</code></td>
                <td><code>{f.sanitized_actor}</code></td>
                <td style={{ fontSize: '12px', color: '#64748b' }}>{f.timestamp.replace('T', ' ').substring(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

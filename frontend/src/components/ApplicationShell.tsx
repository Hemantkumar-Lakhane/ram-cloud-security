import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  Server,
  Layers,
  Activity,
  FileCode2,
  RefreshCw,
  Settings,
  Bell,
  Eye,
  AlertTriangle,
  Database,
  Sliders,
  CheckCircle2,
  FlaskConical,
  Wrench,
  Radio
} from 'lucide-react';

export type WorkspaceMode = 'secops' | 'research' | 'admin';

interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: React.ReactNode;
  badge?: string;
  badgeType?: 'active' | 'soon';
}

interface DomainGroup {
  title: string;
  items: NavItem[];
}

export const ApplicationShell: React.FC<{
  currentRoute: string;
  onRouteChange: (route: string) => void;
  children: React.ReactNode;
  onOpenSearch: () => void;
}> = ({ currentRoute, onRouteChange, children, onOpenSearch }) => {
  // Determine current workspace mode from active route
  const getWorkspaceFromRoute = (route: string): WorkspaceMode => {
    if (route.startsWith('/research')) return 'research';
    if (route.startsWith('/admin')) return 'admin';
    return 'secops';
  };

  const [activeWorkspace, setActiveWorkspace] = useState<WorkspaceMode>(getWorkspaceFromRoute(currentRoute));

  // Sync workspace when route changes
  useEffect(() => {
    setActiveWorkspace(getWorkspaceFromRoute(currentRoute));
  }, [currentRoute]);

  // Define navigation groups per workspace
  const secopsDomains: DomainGroup[] = [
    {
      title: 'Operations & Triage',
      items: [
        { id: 'sec-overview', label: 'Security Overview', path: '/security/overview', icon: <Activity size={15} /> },
        { id: 'sec-findings', label: 'Security Findings', path: '/security/findings', icon: <Shield size={15} />, badge: '42' },
        { id: 'sec-investigation', label: 'Forensic Investigation', path: '/security/investigation', icon: <Eye size={15} /> },
      ],
    },
    {
      title: 'Telemetry & Threats',
      items: [
        { id: 'det-events', label: 'Event Telemetry', path: '/detection/events', icon: <Radio size={15} /> },
        { id: 'det-threats', label: 'Threat Activity', path: '/detection/threats', icon: <AlertTriangle size={15} />, badge: '83 Runs' },
      ],
    },
    {
      title: 'Cloud Posture & Identity',
      items: [
        { id: 'env-assets', label: 'Assets Inventory', path: '/environment/assets', icon: <Server size={15} /> },
        { id: 'env-identities', label: 'IAM Principals', path: '/environment/identities', icon: <Layers size={15} /> },
        { id: 'pos-misconfigs', label: 'Misconfigurations', path: '/posture/misconfigurations', icon: <AlertTriangle size={15} /> },
        { id: 'pos-exposure', label: 'Attack Surface', path: '/posture/exposure', icon: <Activity size={15} /> },
        { id: 'pos-vulns', label: 'Vulnerabilities', path: '/posture/vulnerabilities', icon: <Shield size={15} />, badge: 'Soon', badgeType: 'soon' },
        { id: 'pos-compliance', label: 'Compliance', path: '/posture/compliance', icon: <CheckCircle2 size={15} />, badge: 'Soon', badgeType: 'soon' },
        { id: 'env-workloads', label: 'Workload eBPF', path: '/environment/workloads', icon: <Layers size={15} />, badge: 'Soon', badgeType: 'soon' },
        { id: 'env-network', label: 'Network VPCs', path: '/environment/network', icon: <Activity size={15} />, badge: 'Soon', badgeType: 'soon' },
      ],
    },
    {
      title: 'Remediation & Response',
      items: [
        { id: 'rsp-center', label: 'Safe Response Center', path: '/response/center', icon: <RefreshCw size={15} /> },
        { id: 'rsp-history', label: 'Action Audit History', path: '/response/history', icon: <FileCode2 size={15} /> },
      ],
    },
  ];

  const researchDomains: DomainGroup[] = [
    {
      title: 'Dataset & Ground Truth',
      items: [
        { id: 'res-dataset', label: 'Dataset Card & Provenance', path: '/research/dataset', icon: <Database size={15} /> },
      ],
    },
    {
      title: 'Analytics & Visualization',
      items: [
        { id: 'res-eda', label: 'EDA Analytics & Figures (14)', path: '/research/eda', icon: <FileCode2 size={15} /> },
      ],
    },
    {
      title: 'Models & Evaluation',
      items: [
        { id: 'res-experiments', label: 'Experiments & Benchmarks', path: '/research/experiments', icon: <Sliders size={15} /> },
        { id: 'res-evaluation', label: 'Evaluation Methodology', path: '/research/evaluation', icon: <Shield size={15} /> },
      ],
    },
  ];

  const adminDomains: DomainGroup[] = [
    {
      title: 'Platform Administration',
      items: [
        { id: 'adm-integrations', label: 'Telemetry Connectors', path: '/admin/integrations', icon: <Layers size={15} /> },
        { id: 'adm-policies', label: 'Detection Policies', path: '/admin/policies', icon: <Sliders size={15} /> },
        { id: 'adm-settings', label: 'System Settings & Health', path: '/admin/settings', icon: <Settings size={15} /> },
      ],
    },
  ];

  const currentDomainGroups = activeWorkspace === 'secops'
    ? secopsDomains
    : activeWorkspace === 'research'
      ? researchDomains
      : adminDomains;

  const handleSwitchWorkspace = (mode: WorkspaceMode) => {
    setActiveWorkspace(mode);
    if (mode === 'secops') onRouteChange('/security/overview');
    else if (mode === 'research') onRouteChange('/research/dataset');
    else onRouteChange('/admin/integrations');
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        onOpenSearch();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onOpenSearch]);

  return (
    <div className="app-container">
      {/* Persistent Sidebar */}
      <aside className="sidebar">
        {/* Brand Header */}
        <div className="sidebar-header">
          <Shield size={18} color="#2563eb" />
          <span style={{ fontWeight: 700, letterSpacing: '-0.01em' }}>RAM Cloud Security</span>
        </div>

        {/* Primary Workspace Switcher */}
        <div style={{ padding: '8px 10px', borderBottom: '1px solid #e5e7eb', background: '#f8fafc' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '4px', background: '#e2e8f0', padding: '3px', borderRadius: '4px' }}>
            <button
              onClick={() => handleSwitchWorkspace('secops')}
              title="Security Operations Console"
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '2px',
                padding: '6px 2px',
                border: 'none',
                borderRadius: '3px',
                background: activeWorkspace === 'secops' ? '#ffffff' : 'transparent',
                color: activeWorkspace === 'secops' ? '#0f172a' : '#64748b',
                fontWeight: activeWorkspace === 'secops' ? 700 : 500,
                fontSize: '10px',
                cursor: 'pointer',
                boxShadow: activeWorkspace === 'secops' ? '0 1px 2px rgba(0,0,0,0.08)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <Shield size={13} color={activeWorkspace === 'secops' ? '#2563eb' : '#64748b'} />
              <span>SecOps</span>
            </button>

            <button
              onClick={() => handleSwitchWorkspace('research')}
              title="Research & ML Lab"
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '2px',
                padding: '6px 2px',
                border: 'none',
                borderRadius: '3px',
                background: activeWorkspace === 'research' ? '#ffffff' : 'transparent',
                color: activeWorkspace === 'research' ? '#0f172a' : '#64748b',
                fontWeight: activeWorkspace === 'research' ? 700 : 500,
                fontSize: '10px',
                cursor: 'pointer',
                boxShadow: activeWorkspace === 'research' ? '0 1px 2px rgba(0,0,0,0.08)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <FlaskConical size={13} color={activeWorkspace === 'research' ? '#9333ea' : '#64748b'} />
              <span>Research</span>
            </button>

            <button
              onClick={() => handleSwitchWorkspace('admin')}
              title="Platform Administration"
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '2px',
                padding: '6px 2px',
                border: 'none',
                borderRadius: '3px',
                background: activeWorkspace === 'admin' ? '#ffffff' : 'transparent',
                color: activeWorkspace === 'admin' ? '#0f172a' : '#64748b',
                fontWeight: activeWorkspace === 'admin' ? 700 : 500,
                fontSize: '10px',
                cursor: 'pointer',
                boxShadow: activeWorkspace === 'admin' ? '0 1px 2px rgba(0,0,0,0.08)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <Wrench size={13} color={activeWorkspace === 'admin' ? '#475569' : '#64748b'} />
              <span>Admin</span>
            </button>
          </div>
        </div>

        {/* Grouped Sidebar Navigation */}
        <nav className="sidebar-nav">
          {currentDomainGroups.map((group) => (
            <div key={group.title} className="nav-domain-group">
              <span className="nav-domain-title">{group.title}</span>
              {group.items.map((item) => {
                const isActive = currentRoute === item.path;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''}`}
                    onClick={() => onRouteChange(item.path)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, overflow: 'hidden' }}>
                      {item.icon}
                      <span style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {item.label}
                      </span>
                    </div>
                    {item.badge && (
                      <span
                        style={{
                          fontSize: '9px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: '10px',
                          background: item.badgeType === 'soon' ? '#f1f5f9' : '#fee2e2',
                          color: item.badgeType === 'soon' ? '#64748b' : '#dc2626',
                        }}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Workspace Footer State */}
        <div style={{ padding: '10px 12px', borderTop: '1px solid #e5e7eb', background: '#f8fafc', fontSize: '11px', color: '#64748b' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Workspace:</span>
            <strong style={{ color: activeWorkspace === 'secops' ? '#2563eb' : activeWorkspace === 'research' ? '#9333ea' : '#475569' }}>
              {activeWorkspace === 'secops' ? 'SecOps Console' : activeWorkspace === 'research' ? 'Research & ML Lab' : 'Platform Admin'}
            </strong>
          </div>
        </div>
      </aside>

      {/* Main Content Viewport */}
      <div className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <span className="env-badge">
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#16a34a' }} />
              AWS Capture (invictus-ir/aws_dataset)
            </span>
            <button className="search-trigger" onClick={onOpenSearch}>
              <Search size={14} />
              <span>Search telemetry, actors, findings, research (Ctrl+K)</span>
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {activeWorkspace !== 'research' && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => handleSwitchWorkspace('research')}
                style={{ fontSize: '11px', gap: '4px', color: '#9333ea' }}
              >
                <FlaskConical size={13} />
                Research Lab
              </button>
            )}
            <span
              className="badge badge-high"
              style={{ cursor: 'pointer' }}
              onClick={() => onRouteChange('/security/findings')}
            >
              42 Alerts Active
            </span>
            <button className="btn btn-secondary btn-sm" title="Notifications">
              <Bell size={14} />
            </button>
            <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '12px', color: '#475569' }}>
              SA
            </div>
          </div>
        </header>

        <main className="page-container">{children}</main>
      </div>
    </div>
  );
};

export const CommandPalette: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onSelectRoute: (route: string) => void;
}> = ({ isOpen, onClose, onSelectRoute }) => {
  const [query, setQuery] = useState('');

  if (!isOpen) return null;

  const quickLinks = [
    // SecOps
    { label: 'Security Overview Dashboard', path: '/security/overview', group: 'SecOps' },
    { label: 'Security Findings (42 Baseline A Alerts)', path: '/security/findings', group: 'SecOps' },
    { label: 'Forensic Investigation Workbench', path: '/security/investigation', group: 'SecOps' },
    { label: 'Event Telemetry Explorer (2,900 Records)', path: '/detection/events', group: 'SecOps' },
    { label: 'Threat Activity & Emulation Runs (83 Runs)', path: '/detection/threats', group: 'SecOps' },
    { label: 'IAM Principal Monitor (14 Sanitized Actors)', path: '/environment/identities', group: 'SecOps' },
    { label: 'Cloud Assets Inventory (13 Resources)', path: '/environment/assets', group: 'SecOps' },
    { label: 'Cloud Misconfigurations (13 Drift Alerts)', path: '/posture/misconfigurations', group: 'SecOps' },
    { label: 'Safe Response Center [Dry Run Mode]', path: '/response/center', group: 'SecOps' },
    // Research
    { label: 'Dataset Card & Provenance', path: '/research/dataset', group: 'Research Lab' },
    { label: 'EDA Visual Analytics (14 Figures)', path: '/research/eda', group: 'Research Lab' },
    { label: 'Experiments & Baseline Benchmark Matrix', path: '/research/experiments', group: 'Research Lab' },
    { label: 'Evaluation Methodology & Metrics', path: '/research/evaluation', group: 'Research Lab' },
    // Admin
    { label: 'Telemetry Connectors & Integrations', path: '/admin/integrations', group: 'Admin' },
    { label: 'Detection Policies & Rule Controls', path: '/admin/policies', group: 'Admin' },
    { label: 'System Settings & Health Status', path: '/admin/settings', group: 'Admin' },
  ];

  const filtered = quickLinks.filter(l => l.label.toLowerCase().includes(query.toLowerCase()) || l.group.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" style={{ width: '560px' }} onClick={(e) => e.stopPropagation()}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #e2e8f0', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Search size={16} color="#64748b" />
          <input
            type="text"
            placeholder="Type a command, route, finding, or research query..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            style={{ width: '100%', border: 'none', outline: 'none', fontSize: '13px', background: 'transparent' }}
          />
        </div>
        <div style={{ maxHeight: '320px', overflowY: 'auto', padding: '8px' }}>
          {filtered.map((item) => (
            <div
              key={item.path}
              style={{ padding: '8px 12px', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
              className="nav-item"
              onClick={() => {
                onSelectRoute(item.path);
                onClose();
              }}
            >
              <span>{item.label}</span>
              <span style={{ fontSize: '10px', color: '#94a3b8', background: '#f1f5f9', padding: '2px 6px', borderRadius: '3px' }}>
                {item.group}
              </span>
            </div>
          ))}
          {filtered.length === 0 && (
            <div style={{ padding: '20px', textAlign: 'center', color: '#94a3b8', fontSize: '12px' }}>
              No matching commands or routes found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

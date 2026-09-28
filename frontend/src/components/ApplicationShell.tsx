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
  CheckCircle2
} from 'lucide-react';

interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: React.ReactNode;
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
  const domains: DomainGroup[] = [
    {
      title: 'Security',
      items: [
        { id: 'sec-overview', label: 'Overview', path: '/security/overview', icon: <Activity size={15} /> },
        { id: 'sec-findings', label: 'Findings', path: '/security/findings', icon: <Shield size={15} /> },
        { id: 'sec-investigation', label: 'Investigation', path: '/security/investigation', icon: <Eye size={15} /> },
      ],
    },
    {
      title: 'Environment',
      items: [
        { id: 'env-assets', label: 'Assets', path: '/environment/assets', icon: <Server size={15} /> },
        { id: 'env-identities', label: 'Identities', path: '/environment/identities', icon: <Layers size={15} /> },
        { id: 'env-workloads', label: 'Workloads (Soon)', path: '/environment/workloads', icon: <Layers size={15} /> },
        { id: 'env-network', label: 'Network (Soon)', path: '/environment/network', icon: <Activity size={15} /> },
      ],
    },
    {
      title: 'Posture',
      items: [
        { id: 'pos-misconfigs', label: 'Misconfigurations', path: '/posture/misconfigurations', icon: <AlertTriangle size={15} /> },
        { id: 'pos-vulns', label: 'Vulnerabilities', path: '/posture/vulnerabilities', icon: <Shield size={15} /> },
        { id: 'pos-compliance', label: 'Compliance (Soon)', path: '/posture/compliance', icon: <CheckCircle2 size={15} /> },
        { id: 'pos-exposure', label: 'Exposure', path: '/posture/exposure', icon: <AlertTriangle size={15} /> },
      ],
    },
    {
      title: 'Detection',
      items: [
        { id: 'det-events', label: 'Events Telemetry', path: '/detection/events', icon: <Activity size={15} /> },
        { id: 'det-threats', label: 'Threat Activity', path: '/detection/threats', icon: <AlertTriangle size={15} /> },
      ],
    },
    {
      title: 'Research',
      items: [
        { id: 'res-dataset', label: 'Dataset Card', path: '/research/dataset', icon: <Database size={15} /> },
        { id: 'res-eda', label: 'EDA Figures (14)', path: '/research/eda', icon: <FileCode2 size={15} /> },
        { id: 'res-experiments', label: 'Experiments', path: '/research/experiments', icon: <Sliders size={15} /> },
        { id: 'res-evaluation', label: 'Evaluation', path: '/research/evaluation', icon: <Shield size={15} /> },
      ],
    },
    {
      title: 'Response',
      items: [
        { id: 'rsp-center', label: 'Response Center', path: '/response/center', icon: <RefreshCw size={15} /> },
        { id: 'rsp-history', label: 'Action History', path: '/response/history', icon: <FileCode2 size={15} /> },
      ],
    },
    {
      title: 'Administration',
      items: [
        { id: 'adm-integrations', label: 'Integrations', path: '/admin/integrations', icon: <Layers size={15} /> },
        { id: 'adm-policies', label: 'Policies', path: '/admin/policies', icon: <Sliders size={15} /> },
        { id: 'adm-settings', label: 'Settings', path: '/admin/settings', icon: <Settings size={15} /> },
      ],
    },
  ];

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
        <div className="sidebar-header">
          <Shield size={18} color="#2563eb" />
          <span>RAM Cloud Security</span>
        </div>
        <nav className="sidebar-nav">
          {domains.map((group) => (
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
                    {item.icon}
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>

      {/* Main Content Viewport */}
      <div className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <span className="env-badge">
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#16a34a' }} />
              AWS Lab Capture (invictus-ir/aws_dataset)
            </span>
            <button className="search-trigger" onClick={onOpenSearch}>
              <Search size={14} />
              <span>Search telemetry, actors, rules (Ctrl+K)</span>
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="badge badge-high" style={{ cursor: 'pointer' }} onClick={() => onRouteChange('/security/findings')}>
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
    { label: 'Security Overview Dashboard', path: '/security/overview', group: 'Navigation' },
    { label: 'Security Findings (42 Baseline A Alerts)', path: '/security/findings', group: 'Navigation' },
    { label: 'IAM Principal Monitor (14 Sanitized Actors)', path: '/environment/identities', group: 'Environment' },
    { label: 'Telemetry Event Explorer (2,900 Records)', path: '/detection/events', group: 'Detection' },
    { label: 'Research EDA Explorer (14 Figures)', path: '/research/eda', group: 'Research' },
    { label: 'Experiments Benchmark Matrix', path: '/research/experiments', group: 'Research' },
    { label: 'Safe Response Center [Dry Run Mode]', path: '/response/center', group: 'Response' },
  ];

  const filtered = quickLinks.filter(l => l.label.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" style={{ width: '560px' }} onClick={(e) => e.stopPropagation()}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid #e2e8f0', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Search size={16} color="#64748b" />
          <input
            type="text"
            placeholder="Type a command, route, or resource query..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            style={{ width: '100%', border: 'none', outline: 'none', fontSize: '13px', background: 'transparent' }}
          />
        </div>
        <div style={{ maxHeight: '300px', overflowY: 'auto', padding: '8px' }}>
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
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>{item.group}</span>
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

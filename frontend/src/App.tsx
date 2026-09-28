import React, { useState } from 'react';
import type { SecurityFinding } from './types';
import { ApplicationShell, CommandPalette } from './components/ApplicationShell';
import { DetailDrawer, ActionModal } from './components/Modals';

// Pages
import { SecurityOverview } from './pages/SecurityOverview';
import { SecurityFindings } from './pages/SecurityFindings';
import { IncidentInvestigation } from './pages/IncidentInvestigation';

import {
  AssetsInventory,
  IdentitiesMonitor,
  WorkloadRuntime,
  NetworkTopology
} from './pages/EnvironmentPages';

import {
  Misconfigurations,
  Vulnerabilities,
  ComplianceFrameworks,
  AttackSurfaceExposure
} from './pages/PosturePages';

import {
  TelemetryExplorer,
  ThreatActivity
} from './pages/DetectionPages';

import {
  DatasetProvenance,
  EDAExplorer,
  ExperimentsBenchmark,
  EvaluationProtocol
} from './pages/ResearchPages';

import {
  ResponseCenter,
  ActionHistory
} from './pages/ResponsePages';

import {
  TelemetryIntegrations,
  DetectionPolicies,
  SystemSettings
} from './pages/AdminPages';

export const App: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState<string>('/security/overview');
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [responseModalFinding, setResponseModalFinding] = useState<SecurityFinding | null>(null);
  const [isSearchOpen, setIsSearchOpen] = useState<boolean>(false);

  const renderCurrentPage = () => {
    switch (currentRoute) {
      // Security
      case '/security/overview':
        return <SecurityOverview onSelectFinding={setSelectedFinding} onNavigate={setCurrentRoute} />;
      case '/security/findings':
        return <SecurityFindings onSelectFinding={setSelectedFinding} />;
      case '/security/investigation':
        return <IncidentInvestigation />;

      // Environment
      case '/environment/assets':
        return <AssetsInventory />;
      case '/environment/identities':
        return <IdentitiesMonitor />;
      case '/environment/workloads':
        return <WorkloadRuntime />;
      case '/environment/network':
        return <NetworkTopology />;

      // Posture
      case '/posture/misconfigurations':
        return <Misconfigurations onSelectFinding={setSelectedFinding} />;
      case '/posture/vulnerabilities':
        return <Vulnerabilities />;
      case '/posture/compliance':
        return <ComplianceFrameworks />;
      case '/posture/exposure':
        return <AttackSurfaceExposure onSelectFinding={setSelectedFinding} />;

      // Detection
      case '/detection/events':
        return <TelemetryExplorer />;
      case '/detection/threats':
        return <ThreatActivity />;

      // Research
      case '/research/dataset':
        return <DatasetProvenance />;
      case '/research/eda':
        return <EDAExplorer />;
      case '/research/experiments':
        return <ExperimentsBenchmark />;
      case '/research/evaluation':
        return <EvaluationProtocol />;

      // Response
      case '/response/center':
        return <ResponseCenter onOpenResponseModal={setResponseModalFinding} />;
      case '/response/history':
        return <ActionHistory />;

      // Administration
      case '/admin/integrations':
        return <TelemetryIntegrations />;
      case '/admin/policies':
        return <DetectionPolicies />;
      case '/admin/settings':
        return <SystemSettings />;

      default:
        return <SecurityOverview onSelectFinding={setSelectedFinding} onNavigate={setCurrentRoute} />;
    }
  };

  return (
    <ApplicationShell
      currentRoute={currentRoute}
      onRouteChange={setCurrentRoute}
      onOpenSearch={() => setIsSearchOpen(true)}
    >
      {renderCurrentPage()}

      {/* Forensic Detail Drawer */}
      <DetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onOpenResponseModal={(f) => {
          setSelectedFinding(null);
          setResponseModalFinding(f);
        }}
      />

      {/* Human Authorization Response Modal */}
      <ActionModal
        finding={responseModalFinding}
        isOpen={responseModalFinding !== null}
        onClose={() => setResponseModalFinding(null)}
      />

      {/* Global Command Palette */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectRoute={setCurrentRoute}
      />
    </ApplicationShell>
  );
};

export default App;

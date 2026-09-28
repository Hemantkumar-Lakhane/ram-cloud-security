/**
 * RAM Cloud Security — Data Service Adapter Layer
 * Provides clean asynchronous data access to ingested telemetry and baseline metrics.
 */

import eventsData from '../data/events.json';
import findingsData from '../data/findings.json';
import assetsData from '../data/assets.json';
import identitiesData from '../data/identities.json';
import threatRunsData from '../data/threat_runs.json';
import edaSummaryData from '../data/eda_summary.json';
import baselineMetricsData from '../data/rule_baseline_metrics.json';
import identityMappingData from '../data/identity_mapping.json';

import type {
  TelemetryEvent,
  SecurityFinding,
  AssetRecord,
  IdentityRecord,
  ThreatRun,
  EDASummary,
  BaselineMetrics
} from '../types';

export const dataService = {
  async getEvents(): Promise<TelemetryEvent[]> {
    return eventsData as unknown as TelemetryEvent[];
  },

  async getFindings(): Promise<SecurityFinding[]> {
    return findingsData as unknown as SecurityFinding[];
  },

  async getFindingById(id: string): Promise<SecurityFinding | undefined> {
    const findings = findingsData as unknown as SecurityFinding[];
    return findings.find(f => f.finding_id === id);
  },

  async getAssets(): Promise<AssetRecord[]> {
    return assetsData as unknown as AssetRecord[];
  },

  async getIdentities(): Promise<IdentityRecord[]> {
    return identitiesData as unknown as IdentityRecord[];
  },

  async getThreatRuns(): Promise<ThreatRun[]> {
    return threatRunsData as unknown as ThreatRun[];
  },

  async getEDASummary(): Promise<EDASummary> {
    return edaSummaryData as unknown as EDASummary;
  },

  async getBaselineMetrics(): Promise<BaselineMetrics> {
    return baselineMetricsData as unknown as BaselineMetrics;
  },

  async getIdentityMapping(): Promise<Record<string, string>> {
    return identityMappingData as Record<string, string>;
  }
};

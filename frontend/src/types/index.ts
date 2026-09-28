/**
 * RAM Cloud Security — TypeScript Domain & UI Data Contracts
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'NEW' | 'IN_REVIEW' | 'SUPPRESSED' | 'RESOLVED';
export type OperationalState = 'Active' | 'Empty' | 'Loading' | 'Error' | 'Not Connected' | 'Coming Soon' | 'Not Evaluated' | 'Permission Restricted';
export type ActivityTier = 'Tier 1: Pure Detonation' | 'Tier 2: Stratus Warmup/Cleanup' | 'Tier 3: Operator Terraform' | 'Tier 4: AWS Background/Internal';

export interface TelemetryEvent {
  event_id: string;
  timestamp: string;
  event_name: string;
  event_source: string;
  account_id: string;
  actor_name: string;
  actor_type: string;
  source_ip: string;
  user_agent: string;
  aws_region: string;
  is_error: boolean;
  error_code: string | null;
  error_message: string | null;
  resource_id: string;
  detonation_uuid: string | null;
  tier: ActivityTier;
  is_detonation: boolean;
  sanitized_actor: string;
}

export interface SecurityFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: number;
  detection_type: string;
  event_id: string;
  timestamp: string;
  actor_name: string;
  sanitized_actor: string;
  actor_type: string;
  event_source: string;
  event_name: string;
  resource_id: string;
  evidence: Record<string, any>;
  status: FindingStatus;
  recommended_action: {
    action_name: string;
    playbook: string;
    safety_mode: 'DRY_RUN' | 'LIVE';
  };
}

export interface AssetRecord {
  resource_id: string;
  service: string;
  region: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  findings_count: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface IdentityRecord {
  sanitized_id: string;
  raw_actor_name: string;
  actor_type: string;
  total_events: number;
  error_count: number;
  services: string[];
  first_seen: string;
  last_seen: string;
  findings_count: number;
  tier_breakdown: {
    detonation: number;
    warmup: number;
    operator: number;
    background: number;
  };
}

export interface ThreatRun {
  detonation_uuid: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  services: string[];
  apis: string[];
  findings_count: number;
  detected_by_baseline_a: boolean;
  events_sample: string[];
}

export interface EDASummary {
  dataset_name: string;
  source: string;
  license: string;
  total_records: number;
  time_span: {
    start: string;
    end: string;
    duration_minutes: number;
  };
  four_tier_breakdown: {
    pure_detonation: { count: number; pct: number };
    stratus_warmup_cleanup: { count: number; pct: number };
    operator_terraform: { count: number; pct: number };
    aws_background_internal: { count: number; pct: number };
  };
  distinct_counts: {
    services: number;
    event_names: number;
    actors: number;
    source_ips: number;
  };
  error_metrics: {
    total_errors: number;
    error_rate_pct: number;
    top_error_codes: Record<string, number>;
  };
  top_services: Record<string, number>;
  top_apis: Record<string, number>;
  pure_detonation_apis: Record<string, number>;
  figures_generated: string[];
}

export interface BaselineMetrics {
  experiment: string;
  dataset: string;
  total_events_evaluated: number;
  ground_truth: {
    total_attack_events: number;
    total_benign_events: number;
    attack_prevalence_pct: number;
  };
  detection_summary: {
    total_findings_generated: number;
    true_positive_findings: number;
    false_positive_findings: number;
    distinct_attack_events_detected: number;
    distinct_attack_events_missed: number;
    distinct_benign_events_flagged: number;
  };
  event_level_metrics: {
    precision: number;
    recall: number;
    f1_score: number;
    detection_rate_pct: number;
    false_discovery_rate_pct: number;
  };
  temporal_metrics: {
    first_attack_timestamp: string;
    first_detection_timestamp: string;
    time_to_first_alert_seconds: number;
  };
  findings_by_rule: Record<string, number>;
  findings_by_severity: Record<string, number>;
}

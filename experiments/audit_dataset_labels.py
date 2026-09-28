"""
Independent Dataset Label Audit and Baseline A Validation Script.
Audits the provenance, semantics, overlap, and ground-truth definitions of the Stratus Red Team CloudTrail dataset.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Set
import pandas as pd

from src.detection.rules.engine import RuleEngine
from src.ingestion.cloudtrail import CloudTrailIngestion
from src.preprocessing.parser import CloudTrailParser


def audit_dataset_labels(raw_data_dir: Path, output_json: Path = None) -> Dict[str, Any]:
    """
    Performs rigorous audit of dataset labels, provenance, overlaps, and baseline metric sensitivity.
    """
    print(f"[*] Starting Dataset Label Audit on: {raw_data_dir}")
    
    ingestion = CloudTrailIngestion(file_path=raw_data_dir)
    parser = CloudTrailParser()
    engine = RuleEngine()
    
    raw_records = list(ingestion.ingest())
    total_events = len(raw_records)
    print(f"[+] Loaded {total_events} raw events.")

    # Data profiling & categorization
    records_data = []
    normalized_events = []
    
    stratus_uuid_pattern = re.compile(r"stratus-red-team_([0-9a-fA-F-]+)")
    
    for r in raw_records:
        norm = parser.parse(r)
        normalized_events.append(norm)
        
        ua = r.get("userAgent", "")
        has_stratus = "stratus" in ua.lower()
        has_tf = "terraform" in ua.lower()
        
        match = stratus_uuid_pattern.search(ua)
        detonation_uuid = match.group(1) if match else None
        
        # Determine Activity Tier
        if has_stratus and not has_tf:
            tier = "STRATUS_PURE_DETONATION"
        elif has_stratus and has_tf:
            tier = "STRATUS_TERRAFORM_WARMUP_CLEANUP"
        elif not has_stratus and has_tf:
            tier = "PURE_TERRAFORM_OPERATOR"
        else:
            tier = "AWS_BACKGROUND_INTERNAL"
            
        records_data.append({
            "event_id": norm.event_id,
            "timestamp": norm.timestamp,
            "event_name": norm.event_name,
            "event_source": norm.event_source,
            "account_id": norm.account_id,
            "actor_name": norm.actor_name,
            "actor_type": norm.actor_type,
            "source_ip": norm.source_ip,
            "user_agent": ua,
            "is_error": norm.error_code is not None,
            "error_code": norm.error_code,
            "detonation_uuid": detonation_uuid,
            "tier": tier,
        })
        
    df = pd.DataFrame(records_data)
    
    # Tier breakdown
    tier_counts = df["tier"].value_counts().to_dict()
    distinct_uuids = sorted(list(df[df["detonation_uuid"].notna()]["detonation_uuid"].unique()))
    
    # 1. Attack Events Detailed Breakdown (for the 1,146 Stratus-associated events)
    stratus_df = df[df["tier"].isin(["STRATUS_PURE_DETONATION", "STRATUS_TERRAFORM_WARMUP_CLEANUP"])]
    pure_det_df = df[df["tier"] == "STRATUS_PURE_DETONATION"]
    
    attack_breakdown_by_api = stratus_df["event_name"].value_counts().head(25).to_dict()
    pure_attack_breakdown_by_api = pure_det_df["event_name"].value_counts().to_dict()
    attack_breakdown_by_service = stratus_df["event_source"].value_counts().to_dict()
    attack_breakdown_by_identity = stratus_df["actor_name"].value_counts().to_dict()
    attack_error_counts = stratus_df["error_code"].value_counts(dropna=False).head(10).to_dict()
    
    # 2. Evaluation of Rule Engine Across Tiers
    findings_by_event = defaultdict(list)
    findings_by_tier = Counter()
    findings_by_rule_tier = defaultdict(Counter)
    
    for norm, row in zip(normalized_events, records_data):
        findings = engine.evaluate_event(norm)
        for f in findings:
            tier = row["tier"]
            findings_by_tier[tier] += 1
            findings_by_rule_tier[tier][f.rule_id] += 1
            findings_by_event[norm.event_id].append(f)
            
    total_findings = sum(findings_by_tier.values())
    
    # 3. Multi-Ground-Truth Metrics Calculation
    
    # --- Definition 1: Stratus-Associated Activity (Detonation + Warmup/Cleanup = 1,146 events) ---
    def1_attack_ids = set(df[df["tier"].isin(["STRATUS_PURE_DETONATION", "STRATUS_TERRAFORM_WARMUP_CLEANUP"])]["event_id"])
    def1_tp = sum(1 for ev_id in findings_by_event if ev_id in def1_attack_ids)
    def1_fp = sum(1 for ev_id in findings_by_event if ev_id not in def1_attack_ids)
    def1_fn = len(def1_attack_ids) - def1_tp
    def1_prec = def1_tp / (def1_tp + def1_fp) if (def1_tp + def1_fp) > 0 else 0.0
    def1_rec = def1_tp / len(def1_attack_ids) if def1_attack_ids else 0.0
    def1_f1 = 2 * def1_prec * def1_rec / (def1_prec + def1_rec) if (def1_prec + def1_rec) > 0 else 0.0
    
    # --- Definition 2: Pure Attack Detonations Only (214 events) ---
    def2_attack_ids = set(df[df["tier"] == "STRATUS_PURE_DETONATION"]["event_id"])
    def2_tp = sum(1 for ev_id in findings_by_event if ev_id in def2_attack_ids)
    def2_fp = sum(1 for ev_id in findings_by_event if ev_id not in def2_attack_ids)
    def2_fn = len(def2_attack_ids) - def2_tp
    def2_prec = def2_tp / (def2_tp + def2_fp) if (def2_tp + def2_fp) > 0 else 0.0
    def2_rec = def2_tp / len(def2_attack_ids) if def2_attack_ids else 0.0
    def2_f1 = 2 * def2_prec * def2_rec / (def2_prec + def2_rec) if (def2_prec + def2_rec) > 0 else 0.0

    # --- Definition 3: Technique-Level Detonation Run Coverage (83 Detonation UUIDs) ---
    detonation_run_coverage = {}
    for uuid in distinct_uuids:
        events_in_run = set(df[df["detonation_uuid"] == uuid]["event_id"])
        alerts_in_run = sum(len(findings_by_event[ev_id]) for ev_id in events_in_run)
        detonation_run_coverage[uuid] = alerts_in_run > 0
        
    detected_runs_count = sum(1 for detected in detonation_run_coverage.values() if detected)
    total_runs_count = len(distinct_uuids)
    technique_run_recall = detected_runs_count / total_runs_count if total_runs_count > 0 else 0.0

    audit_results = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_name": "Stratus Red Team CloudTrail Dataset (invictus-ir/aws_dataset)",
        "provenance_and_labeling_semantics": {
            "label_origin": "Derived from User-Agent HTTP headers injected during Stratus Red Team execution",
            "is_native_cloudtrail_label": False,
            "label_type": "Tool/Session Attribution (UUID correlation tag in User-Agent)",
            "total_records": total_events,
            "distinct_detonation_uuids": total_runs_count,
        },
        "four_tier_activity_breakdown": {
            "stratus_pure_detonation": {
                "description": "Direct adversarial API calls executed during the detonate phase",
                "event_count": tier_counts.get("STRATUS_PURE_DETONATION", 0),
                "pct_of_total": round(tier_counts.get("STRATUS_PURE_DETONATION", 0) / total_events * 100, 2),
            },
            "stratus_terraform_warmup_cleanup": {
                "description": "Prerequisite infrastructure provisioning/teardown by Stratus via Terraform",
                "event_count": tier_counts.get("STRATUS_TERRAFORM_WARMUP_CLEANUP", 0),
                "pct_of_total": round(tier_counts.get("STRATUS_TERRAFORM_WARMUP_CLEANUP", 0) / total_events * 100, 2),
            },
            "pure_terraform_operator": {
                "description": "Lab environment infrastructure lifecycle executed by operator (non-Stratus tagged)",
                "event_count": tier_counts.get("PURE_TERRAFORM_OPERATOR", 0),
                "pct_of_total": round(tier_counts.get("PURE_TERRAFORM_OPERATOR", 0) / total_events * 100, 2),
            },
            "aws_background_internal": {
                "description": "Native AWS internal service calls, KMS rotations, console sessions",
                "event_count": tier_counts.get("AWS_BACKGROUND_INTERNAL", 0),
                "pct_of_total": round(tier_counts.get("AWS_BACKGROUND_INTERNAL", 0) / total_events * 100, 2),
            },
        },
        "benign_classification_verification": {
            "previously_classified_benign_count": 1754,
            "actual_composition_of_1754": {
                "pure_terraform_operator": tier_counts.get("PURE_TERRAFORM_OPERATOR", 0),
                "aws_background_internal": tier_counts.get("AWS_BACKGROUND_INTERNAL", 0),
            },
            "is_explicitly_labeled_benign": False,
            "semantics": "Events lacking the 'stratus' token in User-Agent, representing non-adversarial lab management and background cloud operations.",
        },
        "attack_events_distribution": {
            "stratus_associated_total": len(stratus_df),
            "pure_detonation_total": len(pure_det_df),
            "top_services": attack_breakdown_by_service,
            "top_identities": attack_breakdown_by_identity,
            "pure_detonation_apis": pure_attack_breakdown_by_api,
            "top_error_codes": {str(k): v for k, v in attack_error_counts.items()},
        },
        "findings_breakdown_by_tier": {
            "total_findings": total_findings,
            "by_tier": dict(findings_by_tier),
            "by_rule_and_tier": {tier: dict(rules) for tier, rules in findings_by_rule_tier.items()},
        },
        "comparative_ground_truth_evaluations": {
            "definition_1_stratus_associated_all": {
                "description": "Ground Truth = All Stratus-associated events (Detonation + Warmup/Cleanup)",
                "ground_truth_attack_events": len(def1_attack_ids),
                "ground_truth_benign_events": total_events - len(def1_attack_ids),
                "true_positives": def1_tp,
                "false_positives": def1_fp,
                "false_negatives": def1_fn,
                "precision": round(def1_prec, 4),
                "recall": round(def1_rec, 4),
                "f1_score": round(def1_f1, 4),
            },
            "definition_2_pure_detonations_only": {
                "description": "Ground Truth = Pure Stratus detonation events only (Direct Attack APIs)",
                "ground_truth_attack_events": len(def2_attack_ids),
                "ground_truth_benign_events": total_events - len(def2_attack_ids),
                "true_positives": def2_tp,
                "false_positives": def2_fp,
                "false_negatives": def2_fn,
                "precision": round(def2_prec, 4),
                "recall": round(def2_rec, 4),
                "f1_score": round(def2_f1, 4),
            },
            "definition_3_technique_run_level": {
                "description": "Ground Truth = Technique Detonation Runs (Did at least 1 alert fire per attack run?)",
                "total_detonation_runs": total_runs_count,
                "runs_with_at_least_one_finding": detected_runs_count,
                "runs_missed": total_runs_count - detected_runs_count,
                "technique_level_recall": round(technique_run_recall, 4),
            },
        },
    }
    
    print("\n" + "=" * 60)
    print("DATASET LABEL AUDIT SUMMARY")
    print("=" * 60)
    print(f"Total Events: {total_events}")
    print(f"Tier 1 - Pure Detonation Events: {tier_counts.get('STRATUS_PURE_DETONATION', 0)} ({tier_counts.get('STRATUS_PURE_DETONATION', 0)/total_events*100:.2f}%)")
    print(f"Tier 2 - Stratus+Terraform Warmup/Cleanup: {tier_counts.get('STRATUS_TERRAFORM_WARMUP_CLEANUP', 0)} ({tier_counts.get('STRATUS_TERRAFORM_WARMUP_CLEANUP', 0)/total_events*100:.2f}%)")
    print(f"Tier 3 - Pure Terraform Operator: {tier_counts.get('PURE_TERRAFORM_OPERATOR', 0)} ({tier_counts.get('PURE_TERRAFORM_OPERATOR', 0)/total_events*100:.2f}%)")
    print(f"Tier 4 - AWS Background/Internal: {tier_counts.get('AWS_BACKGROUND_INTERNAL', 0)} ({tier_counts.get('AWS_BACKGROUND_INTERNAL', 0)/total_events*100:.2f}%)")
    print("\nBaseline A Metrics Under Ground Truth Definitions:")
    print(f"  [Def 1 - All Stratus-Associated (1,146 evts)]: Precision={def1_prec:.4f}, Recall={def1_rec:.4f}, F1={def1_f1:.4f}")
    print(f"  [Def 2 - Pure Detonations Only (214 evts)]:    Precision={def2_prec:.4f}, Recall={def2_rec:.4f}, F1={def2_f1:.4f}")
    print(f"  [Def 3 - Technique Run Level (83 runs)]:       Technique Recall={technique_run_recall:.4f} ({detected_runs_count}/{total_runs_count} runs detected)")
    print("=" * 60 + "\n")
    
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(audit_results, f, indent=2)
        print(f"[+] Audit report saved to: {output_json}")
        
    return audit_results


if __name__ == "__main__":
    raw_path = Path("data/raw/stratus_cloudtrail/CloudTrail")
    out_path = Path("experiments/results/dataset_label_audit.json")
    audit_dataset_labels(raw_path, out_path)

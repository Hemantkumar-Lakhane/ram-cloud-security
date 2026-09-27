"""
Phase 2 Experiment: Deterministic Rule Baseline Evaluation (Baseline A: Rules Only).
Evaluates the Rule Engine against the real Stratus Red Team CloudTrail dataset (2,900 events).
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

from src.detection.rules.engine import RuleEngine
from src.ingestion.cloudtrail import CloudTrailIngestion
from src.preprocessing.parser import CloudTrailParser


def evaluate_rule_baseline(raw_data_dir: Path, output_metrics_json: Path = None) -> Dict[str, Any]:
    """
    Executes Baseline A evaluation on real CloudTrail telemetry.
    """
    print(f"[*] Starting Baseline A Evaluation on: {raw_data_dir}")
    
    ingestion = CloudTrailIngestion(file_path=raw_data_dir)
    parser = CloudTrailParser()
    engine = RuleEngine()
    
    raw_records = list(ingestion.ingest())
    total_events = len(raw_records)
    print(f"[+] Loaded {total_events} raw events.")
    
    # Ground truth mapping: events executed by Stratus Red Team detonations
    # (Note: userAgent is used ONLY to establish ground truth evaluation labels for benchmarking, NOT by the detection rules)
    events_metadata = []
    normalized_events = []
    
    for r in raw_records:
        norm = parser.parse(r)
        normalized_events.append(norm)
        
        user_agent = r.get("userAgent", "")
        is_attack_ground_truth = "stratus-red-team" in user_agent.lower() or "stratus" in user_agent.lower()
        is_terraform = "terraform" in user_agent.lower()
        
        events_metadata.append({
            "event_id": norm.event_id,
            "timestamp": norm.timestamp,
            "event_name": norm.event_name,
            "event_source": norm.event_source,
            "actor_name": norm.actor_name,
            "is_attack": is_attack_ground_truth,
            "is_terraform": is_terraform,
        })
        
    df_meta = pd.DataFrame(events_metadata)
    total_attack_events = int(df_meta["is_attack"].sum())
    total_benign_events = total_events - total_attack_events
    
    print(f"[+] Ground Truth: {total_attack_events} attack events ({total_attack_events/total_events*100:.2f}%), {total_benign_events} benign events.")
    
    # Execute Rule Engine
    all_findings = []
    findings_by_event_id = defaultdict(list)
    
    for norm in normalized_events:
        findings = engine.evaluate_event(norm)
        for f in findings:
            all_findings.append(f)
            findings_by_event_id[norm.event_id].append(f)
            
    total_findings = len(all_findings)
    print(f"[+] Rule Engine Generated {total_findings} security findings.")
    
    # Analyze Findings against Ground Truth
    tp_findings = []  # Finding fired on attack event
    fp_findings = []  # Finding fired on benign/terraform event
    
    detected_event_ids = set()
    rule_counts = Counter()
    severity_counts = Counter()
    technique_counts = Counter()
    
    for f in all_findings:
        rule_counts[f.rule_id] += 1
        severity_counts[f.severity.value] += 1
        tech = f.evidence.get("mitre_technique_id", "Unknown")
        technique_counts[tech] += 1
        
        ev_id = f.evidence.get("event_id")
        detected_event_ids.add(ev_id)
        
        meta = df_meta[df_meta["event_id"] == ev_id].iloc[0]
        if meta["is_attack"]:
            tp_findings.append(f)
        else:
            fp_findings.append(f)
            
    # Distinct attack events detected vs missed
    detected_attack_events = df_meta[(df_meta["event_id"].isin(detected_event_ids)) & (df_meta["is_attack"])]
    missed_attack_events = df_meta[(~df_meta["event_id"].isin(detected_event_ids)) & (df_meta["is_attack"])]
    
    distinct_tp_events = len(detected_attack_events)
    distinct_missed_events = len(missed_attack_events)
    distinct_fp_events = len(df_meta[(df_meta["event_id"].isin(detected_event_ids)) & (~df_meta["is_attack"])])
    
    # Attack Technique Coverage Analysis
    # Breakdown of what attack API calls were missed by deterministic rules
    missed_attack_apis = missed_attack_events["event_name"].value_counts().to_dict()
    detected_attack_apis = detected_attack_events["event_name"].value_counts().to_dict()
    
    # Event-level Metrics
    # Precision = TP / (TP + FP)
    # Recall = TP / (TP + FN)
    precision = distinct_tp_events / (distinct_tp_events + distinct_fp_events) if (distinct_tp_events + distinct_fp_events) > 0 else 0.0
    recall = distinct_tp_events / total_attack_events if total_attack_events > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # Temporal & Latency Analysis
    if not detected_attack_events.empty:
        first_attack_time = df_meta[df_meta["is_attack"]]["timestamp"].min()
        first_detection_time = detected_attack_events["timestamp"].min()
        detection_latency_seconds = (first_detection_time - first_attack_time).total_seconds()
    else:
        detection_latency_seconds = None

    metrics = {
        "experiment": "Baseline A: Deterministic Rules Only",
        "dataset": "Stratus Red Team CloudTrail Dataset (invictus-ir/aws_dataset)",
        "total_events_evaluated": total_events,
        "ground_truth": {
            "total_attack_events": total_attack_events,
            "total_benign_events": total_benign_events,
            "attack_prevalence_pct": round(total_attack_events / total_events * 100, 2),
        },
        "detection_summary": {
            "total_findings_generated": total_findings,
            "true_positive_findings": len(tp_findings),
            "false_positive_findings": len(fp_findings),
            "distinct_attack_events_detected": distinct_tp_events,
            "distinct_attack_events_missed": distinct_missed_events,
            "distinct_benign_events_flagged": distinct_fp_events,
        },
        "event_level_metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "detection_rate_pct": round(recall * 100, 2),
            "false_discovery_rate_pct": round((1 - precision) * 100, 2) if precision > 0 else 0.0,
        },
        "temporal_metrics": {
            "first_attack_timestamp": str(df_meta[df_meta["is_attack"]]["timestamp"].min()),
            "first_detection_timestamp": str(detected_attack_events["timestamp"].min()) if not detected_attack_events.empty else None,
            "time_to_first_alert_seconds": detection_latency_seconds,
        },
        "findings_by_rule": dict(rule_counts),
        "findings_by_severity": dict(severity_counts),
        "findings_by_mitre_technique": dict(technique_counts),
        "detected_attack_apis_sample": dict(list(detected_attack_apis.items())[:15]),
        "missed_attack_apis_top": dict(list(missed_attack_apis.items())[:20]),
    }
    
    print("\n" + "=" * 60)
    print("BASELINE A (RULES ONLY) EVALUATION METRICS")
    print("=" * 60)
    print(f"Total Findings: {total_findings}")
    print(f"Event Precision: {precision:.4f} | Event Recall: {recall:.4f} | F1: {f1:.4f}")
    print(f"Attack Events Detected: {distinct_tp_events} / {total_attack_events} ({recall*100:.2f}%)")
    print(f"Attack Events Missed: {distinct_missed_events} / {total_attack_events} ({distinct_missed_events/total_attack_events*100:.2f}%)")
    print(f"Benign Events Flagged (FP): {distinct_fp_events}")
    print(f"Time to First Alert: {detection_latency_seconds} seconds")
    print("Findings by Rule:")
    for r_id, cnt in rule_counts.items():
        print(f"  - {r_id}: {cnt}")
    print("=" * 60 + "\n")
    
    if output_metrics_json:
        output_metrics_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_metrics_json, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"[+] Baseline A metrics saved to: {output_metrics_json}")
        
    return metrics


if __name__ == "__main__":
    raw_path = Path("data/raw/stratus_cloudtrail/CloudTrail")
    out_path = Path("experiments/results/rule_baseline_metrics.json")
    evaluate_rule_baseline(raw_path, out_path)

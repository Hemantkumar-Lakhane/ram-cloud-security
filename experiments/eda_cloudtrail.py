"""
Exploratory Data Analysis (EDA) for Real AWS CloudTrail Telemetry Dataset.
Inspects the raw Stratus Red Team CloudTrail dataset (invictus-ir/aws_dataset).
"""

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
import pandas as pd

from src.ingestion.cloudtrail import CloudTrailIngestion
from src.preprocessing.parser import CloudTrailParser


def run_eda(raw_data_dir: Path, output_report_json: Path = None) -> Dict[str, Any]:
    """
    Executes comprehensive Exploratory Data Analysis on the real CloudTrail dataset.
    """
    print(f"[*] Starting EDA on raw dataset at: {raw_data_dir}")
    
    ingestion = CloudTrailIngestion(file_path=raw_data_dir)
    parser = CloudTrailParser()
    
    raw_records = list(ingestion.ingest())
    total_raw_records = len(raw_records)
    print(f"[+] Ingested {total_raw_records} raw CloudTrail records.")
    
    if total_raw_records == 0:
        raise ValueError("No records found in dataset directory.")

    # Convert to NormalizedEvent and tabular representation for analysis
    normalized_records = []
    parsing_errors = 0
    
    for r in raw_records:
        try:
            norm = parser.parse(r)
            normalized_records.append(norm)
        except Exception as e:
            parsing_errors += 1

    print(f"[+] Successfully normalized: {len(normalized_records)} events (Parsing errors: {parsing_errors})")

    # Build DataFrame for statistical profiling
    df_data = []
    for r, norm in zip(raw_records, normalized_records):
        user_identity = r.get("userIdentity") or {}
        user_name = user_identity.get("userName") or user_identity.get("principalId")
        actor_type = user_identity.get("type")
        
        # Check for attack signatures (e.g. Stratus red team user-agent or correlation markers)
        user_agent = r.get("userAgent", "")
        is_stratus_attack = "stratus-red-team" in user_agent.lower() or "stratus" in user_agent.lower()
        is_terraform = "terraform" in user_agent.lower()
        
        df_data.append({
            "event_id": norm.event_id,
            "event_time": norm.timestamp,
            "event_source": norm.event_source,
            "event_name": norm.event_name,
            "aws_region": norm.region,
            "account_id": norm.account_id,
            "actor_name": norm.actor_name,
            "actor_type": norm.actor_type,
            "source_ip": norm.source_ip,
            "user_agent": norm.user_agent,
            "status_code": norm.status_code,
            "error_code": norm.error_code,
            "is_error": norm.error_code is not None,
            "read_only": r.get("readOnly", False),
            "event_category": r.get("eventCategory", "Unknown"),
            "event_type": r.get("eventType", "Unknown"),
            "is_stratus_attack": is_stratus_attack,
            "is_terraform": is_terraform,
        })
        
    df = pd.DataFrame(df_data)
    
    # 1. Dataset Dimensions & Time Span
    min_time = df["event_time"].min()
    max_time = df["event_time"].max()
    time_span_hours = (max_time - min_time).total_seconds() / 3600.0 if total_raw_records > 1 else 0
    
    # 2. Service & Event Distribution
    top_services = df["event_source"].value_counts().to_dict()
    top_events = df["event_name"].value_counts().head(20).to_dict()
    
    # 3. Identity Distribution
    actor_distribution = df["actor_name"].value_counts().to_dict()
    actor_type_distribution = df["actor_type"].value_counts().to_dict()
    
    # 4. Error & Status Distribution
    error_distribution = df["error_code"].value_counts(dropna=False).to_dict()
    error_rate = df["is_error"].mean()
    
    # 5. User-Agent & Activity Breakdown
    stratus_attack_count = int(df["is_stratus_attack"].sum())
    terraform_count = int(df["is_terraform"].sum())
    other_ua_count = int((~df["is_stratus_attack"] & ~df["is_terraform"]).sum())
    
    # 6. Missing Values
    missing_analysis = {col: int(df[col].isna().sum()) for col in df.columns}
    missing_pct = {col: round(df[col].isna().mean() * 100, 2) for col in df.columns}
    
    # 7. Attack Scenarios Identified
    # Inspect attack-specific API calls executed by Stratus Red Team
    attack_events = df[df["is_stratus_attack"]]["event_name"].value_counts().to_dict()
    
    report = {
        "dataset_name": "Stratus Red Team CloudTrail Attack Dataset (invictus-ir/aws_dataset)",
        "source": "https://github.com/invictus-ir/aws_dataset",
        "license": "MIT License",
        "total_events": total_raw_records,
        "total_normalized": len(normalized_records),
        "parsing_errors": parsing_errors,
        "time_span": {
            "start": str(min_time),
            "end": str(max_time),
            "duration_hours": round(time_span_hours, 2),
        },
        "distinct_counts": {
            "services": int(df["event_source"].nunique()),
            "event_names": int(df["event_name"].nunique()),
            "actors": int(df["actor_name"].nunique()),
            "source_ips": int(df["source_ip"].nunique()),
            "regions": int(df["aws_region"].nunique()),
        },
        "activity_breakdown": {
            "stratus_red_team_attack_events": stratus_attack_count,
            "stratus_red_team_attack_pct": round((stratus_attack_count / total_raw_records) * 100, 2),
            "terraform_infrastructure_events": terraform_count,
            "terraform_pct": round((terraform_count / total_raw_records) * 100, 2),
            "standard_aws_background_events": other_ua_count,
            "standard_aws_pct": round((other_ua_count / total_raw_records) * 100, 2),
        },
        "error_metrics": {
            "total_errors": int(df["is_error"].sum()),
            "error_rate_pct": round(error_rate * 100, 2),
            "top_error_codes": {str(k): v for k, v in df[df["is_error"]]["error_code"].value_counts().head(10).items()},
        },
        "top_services": top_services,
        "top_events": top_events,
        "actor_distribution": actor_distribution,
        "actor_type_distribution": actor_type_distribution,
        "attack_events_profile": attack_events,
        "missing_value_analysis": missing_pct,
    }
    
    print("\n" + "=" * 60)
    print("EDA SUMMARY REPORT")
    print("=" * 60)
    print(f"Total Events: {report['total_events']}")
    print(f"Time Range: {report['time_span']['start']} to {report['time_span']['end']} ({report['time_span']['duration_hours']} hours)")
    print(f"Distinct Services: {report['distinct_counts']['services']} | Event Types: {report['distinct_counts']['event_names']}")
    print(f"Stratus Attack Events: {stratus_attack_count} ({report['activity_breakdown']['stratus_red_team_attack_pct']}%)")
    print(f"Terraform Setup/Teardown Events: {terraform_count} ({report['activity_breakdown']['terraform_pct']}%)")
    print(f"Other Background Events: {other_ua_count} ({report['activity_breakdown']['standard_aws_pct']}%)")
    print(f"Top 5 Services: {list(top_services.items())[:5]}")
    print(f"Top 5 Attack APIs: {list(attack_events.items())[:5]}")
    print("=" * 60 + "\n")
    
    if output_report_json:
        output_report_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {output_report_json}")
        
    return report


if __name__ == "__main__":
    raw_path = Path("data/raw/stratus_cloudtrail/CloudTrail")
    out_path = Path("experiments/results/eda_summary.json")
    run_eda(raw_path, out_path)

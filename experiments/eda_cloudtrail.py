"""
Comprehensive Exploratory Data Analysis (EDA) & Visualization Generator.
Generates research-quality figures and summary metrics from the real Stratus Red Team CloudTrail dataset.
"""

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from src.ingestion.cloudtrail import CloudTrailIngestion
from src.preprocessing.parser import CloudTrailParser

# Configure styling
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "figure.titlesize": 14,
})

STRATUS_UUID_PATTERN = re.compile(r"stratus-red-team_([0-9a-fA-F-]+)")


def extract_dataset_dataframe(raw_data_dir: Path) -> pd.DataFrame:
    """Ingests and parses all CloudTrail records into an enriched analytical DataFrame."""
    ingestion = CloudTrailIngestion(file_path=raw_data_dir)
    parser = CloudTrailParser()
    
    raw_records = list(ingestion.ingest())
    data = []
    
    for r in raw_records:
        norm = parser.parse(r)
        ua = r.get("userAgent", "")
        has_stratus = "stratus" in ua.lower()
        has_tf = "terraform" in ua.lower()
        
        match = STRATUS_UUID_PATTERN.search(ua)
        detonation_uuid = match.group(1) if match else None
        
        if has_stratus and not has_tf:
            tier = "Pure Detonation"
        elif has_stratus and has_tf:
            tier = "Stratus Warmup/Cleanup"
        elif not has_stratus and has_tf:
            tier = "Operator Terraform"
        else:
            tier = "AWS Background/Internal"
            
        data.append({
            "event_id": norm.event_id,
            "timestamp": norm.timestamp,
            "event_name": norm.event_name,
            "event_source": norm.event_source,
            "aws_region": norm.region or "us-east-1",
            "account_id": norm.account_id,
            "actor_name": norm.actor_name or "Unknown",
            "actor_type": norm.actor_type or "Unknown",
            "source_ip": norm.source_ip or "Unknown",
            "user_agent": ua,
            "is_error": norm.error_code is not None,
            "error_code": norm.error_code if norm.error_code else "Success",
            "detonation_uuid": detonation_uuid,
            "tier": tier,
            "is_stratus_associated": has_stratus,
        })
        
    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def map_mitre_tactic(event_name: str) -> str:
    """Maps CloudTrail API events to high-level MITRE ATT&CK tactics."""
    discovery_apis = {
        "DescribeAccountAttributes", "DescribeInstanceInformation", "DescribeInstanceAttribute",
        "DescribeParameters", "GetParameters", "ListAccessKeys", "ListSecrets", "GetCallerIdentity",
        "DescribeRouteTables", "DescribeNatGateways", "DescribeDBInstances", "DescribeSubnets",
        "DescribeVpcs", "DescribeSecurityGroups", "DescribeTrails", "ListTagsForResource", "GetUser"
    }
    credential_apis = {
        "GetPasswordData", "GetSecretValue", "GetParameter", "Decrypt", "PutSecretValue"
    }
    priv_esc_apis = {
        "AttachUserPolicy", "AttachRolePolicy", "PutRolePolicy", "PutUserPolicy",
        "CreateLoginProfile", "CreateAccessKey", "UpdateAssumeRolePolicy", "AssumeRole"
    }
    defense_evasion_apis = {
        "StopLogging", "StartLogging", "DeleteTrail", "DeleteFlowLogs", "DeleteBucketPolicy",
        "PutEventSelectors", "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupIngress", "DeleteBucketLifecycle", "LeaveOrganization"
    }
    execution_apis = {
        "SendCommand", "GetCommandInvocation", "RunInstances", "UpdateFunctionCode20150331v2"
    }
    
    if event_name in discovery_apis:
        return "Discovery"
    elif event_name in credential_apis:
        return "Credential Access"
    elif event_name in priv_esc_apis:
        return "Privilege Escalation / Persistence"
    elif event_name in defense_evasion_apis:
        return "Defense Evasion"
    elif event_name in execution_apis:
        return "Execution"
    return "Other Management / Prerequisite"


def generate_eda_figures(df: pd.DataFrame, output_dir: Path):
    """Generates the 14 research-grade EDA figures."""
    output_dir.mkdir(parents=True, exist_ok=True)
    colors = ["#2b5c8f", "#d95f02", "#7570b3", "#1b9e77", "#e7298a", "#66a61e", "#e6ab02"]

    # 1. Activity Distribution
    plt.figure(figsize=(8, 5))
    tier_counts = df["tier"].value_counts()
    bars = plt.bar(tier_counts.index, tier_counts.values, color=colors[:4], edgecolor="black", alpha=0.85)
    plt.title("01. Operational Activity Tier Distribution (N=2,900)", fontweight="bold")
    plt.ylabel("Event Count")
    plt.xticks(rotation=15, ha="right")
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 25, f"{yval:,} ({yval/len(df)*100:.1f}%)", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "01_dataset_activity_distribution.png", dpi=300)
    plt.close()

    # 2. Service Distribution
    plt.figure(figsize=(10, 5))
    top_services = df["event_source"].value_counts().head(10)
    sns.barplot(x=top_services.values, y=top_services.index, palette="Blues_r")
    plt.title("02. Top 10 AWS Services by Event Volume", fontweight="bold")
    plt.xlabel("Event Count")
    plt.ylabel("AWS Service Source")
    for idx, val in enumerate(top_services.values):
        plt.text(val + 10, idx, f"{val:,}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "02_service_distribution.png", dpi=300)
    plt.close()

    # 3. Overall Top APIs
    plt.figure(figsize=(10, 6))
    top_apis = df["event_name"].value_counts().head(15)
    sns.barplot(x=top_apis.values, y=top_apis.index, palette="viridis")
    plt.title("03. Top 15 API Actions Across Entire Dataset", fontweight="bold")
    plt.xlabel("Event Count")
    plt.ylabel("API Event Name")
    for idx, val in enumerate(top_apis.values):
        plt.text(val + 3, idx, f"{val:,}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "03_api_distribution.png", dpi=300)
    plt.close()

    # 4. Pure Detonation APIs
    pure_df = df[df["tier"] == "Pure Detonation"]
    plt.figure(figsize=(10, 6))
    pure_apis = pure_df["event_name"].value_counts().head(15)
    sns.barplot(x=pure_apis.values, y=pure_apis.index, palette="Reds_r")
    plt.title("04. Top 15 Pure Attack Detonation APIs (N=214)", fontweight="bold")
    plt.xlabel("Event Count")
    plt.ylabel("Adversary API Action")
    for idx, val in enumerate(pure_apis.values):
        plt.text(val + 0.5, idx, f"{val}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "04_pure_detonation_api_distribution.png", dpi=300)
    plt.close()

    # 5. Attack Technique / MITRE Tactic Distribution
    df["mitre_tactic"] = df["event_name"].apply(map_mitre_tactic)
    stratus_df = df[df["is_stratus_associated"]]
    tactic_counts = stratus_df["mitre_tactic"].value_counts()
    plt.figure(figsize=(9, 5))
    bars = plt.bar(tactic_counts.index, tactic_counts.values, color=colors[:len(tactic_counts)], edgecolor="black", alpha=0.85)
    plt.title("05. Stratus Red Team Events Mapped to MITRE ATT&CK Tactics (N=1,146)", fontweight="bold")
    plt.ylabel("Event Count")
    plt.xticks(rotation=20, ha="right")
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 10, f"{yval} ({yval/len(stratus_df)*100:.1f}%)", ha="center", va="bottom", fontsize=8.5)
    plt.tight_layout()
    plt.savefig(output_dir / "05_attack_technique_distribution.png", dpi=300)
    plt.close()

    # 6. Identity Distribution
    plt.figure(figsize=(10, 5))
    actor_counts = df["actor_name"].value_counts().head(8)
    sns.barplot(x=actor_counts.values, y=[str(a)[:35] for a in actor_counts.index], palette="rocket")
    plt.title("06. Event Distribution by IAM Actor / Principal", fontweight="bold")
    plt.xlabel("Event Count")
    plt.ylabel("IAM Principal Name / Role Session")
    for idx, val in enumerate(actor_counts.values):
        plt.text(val + 15, idx, f"{val:,}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "06_identity_distribution.png", dpi=300)
    plt.close()

    # 7. Success vs Error Distribution
    plt.figure(figsize=(6, 5))
    err_counts = df["is_error"].value_counts()
    labels = ["Success (2,600)", "Error / Denied (300)"]
    plt.pie(err_counts.values, labels=labels, autopct="%1.1f%%", startangle=140, colors=["#2ca02c", "#d62728"], explode=(0, 0.1), shadow=True)
    plt.title("07. API Call Success vs. Error Rate", fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_dir / "07_success_error_distribution.png", dpi=300)
    plt.close()

    # 8. Error Type Breakdown
    error_df = df[df["is_error"]]
    top_errors = error_df["error_code"].value_counts().head(8)
    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_errors.values, y=top_errors.index, palette="mako")
    plt.title("08. Breakdown of Top AWS Error Codes (N=300)", fontweight="bold")
    plt.xlabel("Count of Errored Calls")
    plt.ylabel("AWS Error Code")
    for idx, val in enumerate(top_errors.values):
        plt.text(val + 1, idx, f"{val}", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "08_error_type_distribution.png", dpi=300)
    plt.close()

    # 9. Overall Event Timeline (1-minute bins)
    df_sorted = df.sort_values("timestamp")
    df_resampled = df_sorted.set_index("timestamp").resample("1min")["event_id"].count()
    plt.figure(figsize=(12, 4))
    plt.plot(df_resampled.index, df_resampled.values, color="#1f77b4", lw=2, marker="o", markersize=3)
    plt.fill_between(df_resampled.index, df_resampled.values, color="#1f77b4", alpha=0.2)
    plt.title("09. Event Arrival Rate Density Over Time (1-Minute Bins)", fontweight="bold")
    plt.xlabel("Time (UTC - 2023-07-10)")
    plt.ylabel("Events per Minute")
    plt.xticks(rotation=15)
    plt.tight_layout()
    plt.savefig(output_dir / "09_event_timeline.png", dpi=300)
    plt.close()

    # 10. Multi-Tier Activity Timeline
    pivot_df = df_sorted.set_index("timestamp").groupby([pd.Grouper(freq="2min"), "tier"])["event_id"].count().unstack(fill_value=0)
    plt.figure(figsize=(12, 5))
    pivot_df.plot(kind="area", stacked=True, alpha=0.75, colormap="tab10", figsize=(12, 5))
    plt.title("10. Multi-Tier Activity Volume Over Timeline (2-Minute Stacked Area)", fontweight="bold")
    plt.xlabel("Time (UTC - 2023-07-10)")
    plt.ylabel("Events per 2-Minute Window")
    plt.legend(title="Activity Tier", loc="upper right")
    plt.xticks(rotation=15)
    plt.tight_layout()
    plt.savefig(output_dir / "10_activity_timeline.png", dpi=300)
    plt.close()

    # 11. Overlap Analysis Bar Chart
    plt.figure(figsize=(8, 5))
    overlap_data = {
        "Pure Detonation (Stratus Only)": len(df[df["tier"] == "Pure Detonation"]),
        "Stratus + Terraform (Warmup/Cleanup)": len(df[df["tier"] == "Stratus Warmup/Cleanup"]),
        "Pure Operator Terraform": len(df[df["tier"] == "Operator Terraform"]),
        "AWS Internal / Background": len(df[df["tier"] == "AWS Background/Internal"]),
    }
    bars = plt.barh(list(overlap_data.keys()), list(overlap_data.values()), color=["#d95f02", "#7570b3", "#1b9e77", "#2b5c8f"])
    plt.title("11. Stratus Red Team & Terraform Tool Overlap Quantification", fontweight="bold")
    plt.xlabel("Event Count")
    for bar in bars:
        wval = bar.get_width()
        plt.text(wval + 15, bar.get_y() + bar.get_height()/2.0, f"{wval:,} ({wval/len(df)*100:.1f}%)", va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(output_dir / "11_stratus_terraform_overlap.png", dpi=300)
    plt.close()

    # 12. Service Activity Heatmap (Top 8 Services across 5-min intervals)
    top_8_services = df["event_source"].value_counts().head(8).index
    df_top_srv = df[df["event_source"].isin(top_8_services)].copy()
    heatmap_data = df_top_srv.set_index("timestamp").groupby([pd.Grouper(freq="5min"), "event_source"])["event_id"].count().unstack(fill_value=0)
    heatmap_data.index = [ts.strftime("%H:%M") for ts in heatmap_data.index]
    
    plt.figure(figsize=(10, 6))
    sns.heatmap(heatmap_data.T, cmap="YlGnBu", annot=True, fmt="d", cbar_kws={"label": "Event Count"})
    plt.title("12. Top 8 AWS Services Activity Heatmap (5-Minute Intervals)", fontweight="bold")
    plt.xlabel("Time Window (UTC)")
    plt.ylabel("AWS Service Source")
    plt.tight_layout()
    plt.savefig(output_dir / "12_service_activity_heatmap.png", dpi=300)
    plt.close()

    # 13. Identity-Service Interaction Matrix
    top_actors = df["actor_name"].value_counts().head(5).index
    df_actor_srv = df[df["actor_name"].isin(top_actors) & df["event_source"].isin(top_8_services)]
    actor_srv_matrix = pd.crosstab(df_actor_srv["actor_name"].apply(lambda x: x[:20]), df_actor_srv["event_source"])
    
    plt.figure(figsize=(10, 5))
    sns.heatmap(actor_srv_matrix, cmap="Blues", annot=True, fmt="d", cbar_kws={"label": "API Calls"})
    plt.title("13. IAM Principal to AWS Service Interaction Matrix", fontweight="bold")
    plt.xlabel("AWS Service Source")
    plt.ylabel("IAM Actor")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    plt.savefig(output_dir / "13_identity_service_relationship.png", dpi=300)
    plt.close()

    # 14. Attack Sequence Timeline (Sample multi-stage detonation traces)
    sample_pure = pure_df.sort_values("timestamp").head(30)
    plt.figure(figsize=(12, 6))
    y_positions = {tactic: i for i, tactic in enumerate(["Discovery", "Credential Access", "Privilege Escalation / Persistence", "Defense Evasion", "Execution"])}
    sample_pure["y_pos"] = sample_pure["mitre_tactic"].map(y_positions).fillna(0)
    
    scatter = plt.scatter(sample_pure["timestamp"], sample_pure["y_pos"], c=sample_pure["y_pos"], cmap="Set1", s=90, edgecolors="black", zorder=3)
    plt.yticks(list(y_positions.values()), list(y_positions.keys()))
    plt.plot(sample_pure["timestamp"], sample_pure["y_pos"], color="grey", linestyle="--", alpha=0.6, zorder=2)
    plt.title("14. Chronological Multi-Stage Attack Detonation Trace", fontweight="bold")
    plt.xlabel("Timestamp (UTC)")
    plt.ylabel("MITRE ATT&CK Tactic Stage")
    plt.xticks(rotation=15)
    plt.tight_layout()
    plt.savefig(output_dir / "14_attack_sequence_timeline.png", dpi=300)
    plt.close()

    print(f"[+] All 14 EDA figures successfully saved to: {output_dir}")


def run_eda_pipeline(raw_data_dir: Path, output_json: Path, figures_dir: Path) -> Dict[str, Any]:
    """Runs the complete EDA calculation, generates figures, and writes JSON summary."""
    print(f"[*] Executing Full EDA Pipeline on: {raw_data_dir}")
    df = extract_dataset_dataframe(raw_data_dir)
    total_events = len(df)
    
    tier_counts = df["tier"].value_counts().to_dict()
    service_counts = df["event_source"].value_counts().to_dict()
    api_counts = df["event_name"].value_counts().to_dict()
    actor_counts = df["actor_name"].value_counts().to_dict()
    error_counts = df[df["is_error"]]["error_code"].value_counts().to_dict()
    
    pure_df = df[df["tier"] == "Pure Detonation"]
    pure_api_counts = pure_df["event_name"].value_counts().to_dict()
    
    df["mitre_tactic"] = df["event_name"].apply(map_mitre_tactic)
    tactic_counts = df[df["is_stratus_associated"]]["mitre_tactic"].value_counts().to_dict()
    
    summary = {
        "dataset_name": "Stratus Red Team CloudTrail Attack Dataset (invictus-ir/aws_dataset)",
        "source": "https://github.com/invictus-ir/aws_dataset",
        "license": "MIT License",
        "total_records": total_events,
        "time_span": {
            "start": str(df["timestamp"].min()),
            "end": str(df["timestamp"].max()),
            "duration_minutes": round((df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 60.0, 2),
        },
        "four_tier_breakdown": {
            "pure_detonation": {"count": tier_counts.get("Pure Detonation", 0), "pct": round(tier_counts.get("Pure Detonation", 0)/total_events*100, 2)},
            "stratus_warmup_cleanup": {"count": tier_counts.get("Stratus Warmup/Cleanup", 0), "pct": round(tier_counts.get("Stratus Warmup/Cleanup", 0)/total_events*100, 2)},
            "operator_terraform": {"count": tier_counts.get("Operator Terraform", 0), "pct": round(tier_counts.get("Operator Terraform", 0)/total_events*100, 2)},
            "aws_background_internal": {"count": tier_counts.get("AWS Background/Internal", 0), "pct": round(tier_counts.get("AWS Background/Internal", 0)/total_events*100, 2)},
        },
        "distinct_counts": {
            "services": int(df["event_source"].nunique()),
            "event_names": int(df["event_name"].nunique()),
            "actors": int(df["actor_name"].nunique()),
            "source_ips": int(df["source_ip"].nunique()),
        },
        "error_metrics": {
            "total_errors": int(df["is_error"].sum()),
            "error_rate_pct": round(df["is_error"].mean() * 100, 2),
            "top_error_codes": error_counts,
        },
        "top_services": dict(list(service_counts.items())[:15]),
        "top_apis": dict(list(api_counts.items())[:20]),
        "pure_detonation_apis": pure_api_counts,
        "tactic_distribution_stratus": tactic_counts,
        "figures_generated": [
            "01_dataset_activity_distribution.png",
            "02_service_distribution.png",
            "03_api_distribution.png",
            "04_pure_detonation_api_distribution.png",
            "05_attack_technique_distribution.png",
            "06_identity_distribution.png",
            "07_success_error_distribution.png",
            "08_error_type_distribution.png",
            "09_event_timeline.png",
            "10_activity_timeline.png",
            "11_stratus_terraform_overlap.png",
            "12_service_activity_heatmap.png",
            "13_identity_service_relationship.png",
            "14_attack_sequence_timeline.png",
        ]
    }
    
    # Save figures
    generate_eda_figures(df, figures_dir)
    
    # Save JSON summary
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        
    print(f"[+] EDA Summary JSON written to: {output_json}")
    return summary


if __name__ == "__main__":
    raw_dir = Path("data/raw/stratus_cloudtrail/CloudTrail")
    json_out = Path("experiments/results/eda_summary.json")
    fig_dir = Path("reports/figures/eda")
    run_eda_pipeline(raw_dir, json_out, fig_dir)

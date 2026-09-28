"""
RAM Cloud Security — Frontend Data Exporter
Extracts real dataset telemetry, rule engine findings, EDA summaries, and baseline metrics
into structured JSON bundles for the frontend data adapter layer.
Also copies the 14 generated research figures to frontend/public/figures/eda/.
"""

import json
from pathlib import Path
import re
import shutil
import sys

# Project root setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detection.rules.engine import RuleEngine
from src.ingestion.cloudtrail import CloudTrailIngestion
from src.preprocessing.parser import CloudTrailParser


def export_all():
    raw_data_dir = PROJECT_ROOT / "data/raw/stratus_cloudtrail/CloudTrail"
    frontend_data_dir = PROJECT_ROOT / "frontend/src/data"
    frontend_public_eda = PROJECT_ROOT / "frontend/public/figures/eda"
    
    frontend_data_dir.mkdir(parents=True, exist_ok=True)
    frontend_public_eda.mkdir(parents=True, exist_ok=True)
    
    print("[*] Ingesting and evaluating real CloudTrail dataset...")
    ingestion = CloudTrailIngestion(file_path=raw_data_dir)
    parser = CloudTrailParser()
    engine = RuleEngine()
    
    raw_events = list(ingestion.ingest())
    print(f"[+] Loaded {len(raw_events)} raw events.")
    
    # 1. Parse & Normalize
    events = []
    stratus_uuid_pattern = re.compile(r"stratus-red-team_([0-9a-fA-F-]+)")
    
    for raw in raw_events:
        norm = parser.parse(raw)
        ua = raw.get("userAgent", "")
        ua_lower = ua.lower()
        has_stratus = "stratus" in ua_lower
        has_tf = "terraform" in ua_lower
        match = stratus_uuid_pattern.search(ua)
        uuid = match.group(1) if match else None
        
        if has_stratus and not has_tf:
            tier = "Tier 1: Pure Detonation"
            is_detonation = True
        elif has_stratus and has_tf:
            tier = "Tier 2: Stratus Warmup/Cleanup"
            is_detonation = False
        elif not has_stratus and has_tf:
            tier = "Tier 3: Operator Terraform"
            is_detonation = False
        else:
            tier = "Tier 4: AWS Background/Internal"
            is_detonation = False
            
        res_id = None
        if norm.resources and len(norm.resources) > 0:
            res_id = norm.resources[0].get("ARN") or norm.resources[0].get("arn")
        if not res_id:
            res_id = f"arn:aws:{norm.event_source.replace('.amazonaws.com', '')}:{norm.region or 'us-east-1'}:{norm.account_id or '123456789012'}:resource/{norm.event_name.lower()}"

        events.append({
            "event_id": norm.event_id,
            "timestamp": norm.timestamp.isoformat(),
            "event_name": norm.event_name,
            "event_source": norm.event_source.replace(".amazonaws.com", "") if norm.event_source else "unknown",
            "account_id": norm.account_id or "123456789012",
            "actor_name": norm.actor_name or "unknown",
            "actor_type": norm.actor_type or "Unknown",
            "source_ip": norm.source_ip or "unknown",
            "user_agent": ua,
            "aws_region": norm.region or "us-east-1",
            "is_error": norm.error_code is not None,
            "error_code": norm.error_code,
            "error_message": norm.error_message,
            "resource_id": res_id,
            "detonation_uuid": uuid,
            "tier": tier,
            "is_detonation": is_detonation,
        })
        
    # Sort events by timestamp
    events.sort(key=lambda x: x["timestamp"])
    
    # Deterministic Identity Sanitization Mapping
    unique_actors = sorted(list(set(e["actor_name"] for e in events)))
    identity_map = {}
    role_counter = 1
    user_counter = 1
    service_counter = 1
    other_counter = 1
    
    for raw_actor in unique_actors:
        actor_type = next((e["actor_type"] for e in events if e["actor_name"] == raw_actor), "Unknown")
        if "role" in raw_actor.lower() or "aroa" in raw_actor.lower() or actor_type == "AssumedRole":
            identity_map[raw_actor] = f"Role-{role_counter:02d}"
            role_counter += 1
        elif "user" in raw_actor.lower() or "aida" in raw_actor.lower() or actor_type in ["IAMUser", "Root"]:
            identity_map[raw_actor] = f"IAMUser-{user_counter:02d}"
            user_counter += 1
        elif "service" in raw_actor.lower() or actor_type in ["AWSService", "AWSAccount"]:
            identity_map[raw_actor] = f"AWSService-{service_counter:02d}"
            service_counter += 1
        else:
            identity_map[raw_actor] = f"Identity-{other_counter:02d}"
            other_counter += 1
            
    for e in events:
        e["sanitized_actor"] = identity_map.get(e["actor_name"], "Identity-00")
        
    # 2. Evaluate Rule Engine Findings
    findings = []
    finding_counter = 1
    for raw in raw_events:
        norm = parser.parse(raw)
        f_list = engine.evaluate_event(norm)
        for f in f_list:
            sanitized_actor = identity_map.get(norm.actor_name or "unknown", "Identity-00")
            findings.append({
                "finding_id": f"FINDING-{f.rule_id or 'RULE'}-{finding_counter:03d}",
                "rule_id": f.rule_id or "RULE-UNKNOWN",
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence,
                "detection_type": f.detection_type.value if hasattr(f.detection_type, "value") else str(f.detection_type),
                "event_id": norm.event_id,
                "timestamp": f.timestamp.isoformat(),
                "actor_name": norm.actor_name or "unknown",
                "sanitized_actor": sanitized_actor,
                "actor_type": norm.actor_type or "Unknown",
                "event_source": norm.event_source.replace(".amazonaws.com", ""),
                "event_name": norm.event_name,
                "resource_id": f.resource or norm.resource_id or f"arn:aws:cloudtrail:us-east-1:{norm.account_id or '123456789012'}:trail/GlobalSecurityTrail",
                "evidence": f.evidence or {"matched_event": norm.event_name, "rule": f.rule_id},
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "recommended_action": {
                    "action_name": "aws:cloudtrail:StartLogging" if "CFG" in (f.rule_id or "") else "aws:iam:DeactivateAccessKey",
                    "playbook": f.recommended_action or f"Automated Remediation Playbook for {f.rule_id}",
                    "safety_mode": "DRY_RUN",
                }
            })
            finding_counter += 1
            
    # Sort findings by timestamp descending
    findings.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # 3. Compile Asset Inventory
    assets_map = {}
    for e in events:
        res = e["resource_id"]
        if res not in assets_map:
            assets_map[res] = {
                "resource_id": res,
                "service": e["event_source"],
                "region": e["aws_region"],
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "event_count": 0,
                "findings_count": 0,
                "risk_level": "LOW",
            }
        assets_map[res]["event_count"] += 1
        assets_map[res]["last_seen"] = e["timestamp"]
        
    for f in findings:
        res = f["resource_id"]
        if res in assets_map:
            assets_map[res]["findings_count"] += 1
            assets_map[res]["risk_level"] = "CRITICAL" if f["severity"] == "CRITICAL" else "HIGH"
            
    assets = list(assets_map.values())
    assets.sort(key=lambda x: (x["findings_count"], x["event_count"]), reverse=True)
    
    # 4. Compile Identities Inventory
    identities_map = {}
    for e in events:
        actor = e["sanitized_actor"]
        raw_name = e["actor_name"]
        if actor not in identities_map:
            identities_map[actor] = {
                "sanitized_id": actor,
                "raw_actor_name": raw_name,
                "actor_type": e["actor_type"],
                "total_events": 0,
                "error_count": 0,
                "services": set(),
                "first_seen": e["timestamp"],
                "last_seen": e["timestamp"],
                "findings_count": 0,
                "tier_breakdown": {"detonation": 0, "warmup": 0, "operator": 0, "background": 0},
            }
        identities_map[actor]["total_events"] += 1
        if e["is_error"]:
            identities_map[actor]["error_count"] += 1
        identities_map[actor]["services"].add(e["event_source"])
        identities_map[actor]["last_seen"] = e["timestamp"]
        
        tier = e["tier"]
        if "Pure Detonation" in tier:
            identities_map[actor]["tier_breakdown"]["detonation"] += 1
        elif "Warmup" in tier:
            identities_map[actor]["tier_breakdown"]["warmup"] += 1
        elif "Operator" in tier:
            identities_map[actor]["tier_breakdown"]["operator"] += 1
        else:
            identities_map[actor]["tier_breakdown"]["background"] += 1
            
    for f in findings:
        actor = f["sanitized_actor"]
        if actor in identities_map:
            identities_map[actor]["findings_count"] += 1
            
    identities = []
    for item in identities_map.values():
        item["services"] = sorted(list(item["services"]))
        identities.append(item)
    identities.sort(key=lambda x: x["total_events"], reverse=True)
    
    # 5. Compile Emulation Runs (Threat Activity)
    runs_map = {}
    for e in events:
        uuid = e["detonation_uuid"]
        if uuid:
            if uuid not in runs_map:
                runs_map[uuid] = {
                    "detonation_uuid": uuid,
                    "event_count": 0,
                    "events": [],
                    "first_seen": e["timestamp"],
                    "last_seen": e["timestamp"],
                    "services": set(),
                    "apis": set(),
                    "findings_count": 0,
                    "detected_by_baseline_a": False,
                }
            runs_map[uuid]["event_count"] += 1
            runs_map[uuid]["events"].append(e["event_id"])
            runs_map[uuid]["services"].add(e["event_source"])
            runs_map[uuid]["apis"].add(e["event_name"])
            runs_map[uuid]["last_seen"] = e["timestamp"]
            
    for f in findings:
        # Check if finding belongs to any run event
        for r in runs_map.values():
            if f["event_id"] in r["events"]:
                r["findings_count"] += 1
                r["detected_by_baseline_a"] = True
                
    runs = []
    for r in runs_map.values():
        r["services"] = sorted(list(r["services"]))
        r["apis"] = sorted(list(r["apis"]))
        r["events_sample"] = r["events"][:5]
        del r["events"]
        runs.append(r)
    runs.sort(key=lambda x: x["first_seen"])
    
    # 6. Load EDA Summary & Baseline Metrics
    eda_summary_path = PROJECT_ROOT / "experiments/results/eda_summary.json"
    rule_metrics_path = PROJECT_ROOT / "experiments/results/rule_baseline_metrics.json"
    
    with open(eda_summary_path, "r", encoding="utf-8") as f:
        eda_summary = json.load(f)
    with open(rule_metrics_path, "r", encoding="utf-8") as f:
        rule_metrics = json.load(f)
        
    # Write JSON files to frontend/src/data/
    def write_json(filename, data):
        dest = frontend_data_dir / filename
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Wrote: {dest} ({len(data) if isinstance(data, list) else 'dict'} entries)")
        
    write_json("events.json", events[:500])  # Top 500 recent events for fast rendering
    write_json("all_events_meta.json", {
        "total_records": len(events),
        "time_start": events[0]["timestamp"],
        "time_end": events[-1]["timestamp"],
        "distinct_services": len(set(e["event_source"] for e in events)),
        "distinct_actors": len(identities),
        "distinct_apis": len(set(e["event_name"] for e in events)),
    })
    write_json("findings.json", findings)
    write_json("assets.json", assets[:50])
    write_json("identities.json", identities)
    write_json("threat_runs.json", runs)
    write_json("eda_summary.json", eda_summary)
    write_json("rule_baseline_metrics.json", rule_metrics)
    write_json("identity_mapping.json", identity_map)
    
    # Copy 14 EDA figures to frontend/public/figures/eda/
    eda_fig_src = PROJECT_ROOT / "reports/figures/eda"
    copied_count = 0
    for fig_file in eda_fig_src.glob("*.png"):
        shutil.copy2(fig_file, frontend_public_eda / fig_file.name)
        copied_count += 1
    print(f"[+] Copied {copied_count} EDA figures to: {frontend_public_eda}")
    print("[*] Frontend data export complete!")


if __name__ == "__main__":
    export_all()

"""
Unit tests for CloudTrailIngestion across local JSON, JSONL, gzip archives, and read-only S3.
"""

import gzip
import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src.common.constants import TelemetrySource
from src.ingestion.cloudtrail import CloudTrailIngestion


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cloudtrail"


def test_ingest_single_json_fixture():
    """Verifies ingestion of a single-object CloudTrail JSON file."""
    fixture_path = FIXTURES_DIR / "normal_event.json"
    collector = CloudTrailIngestion(file_path=fixture_path)
    
    events = list(collector.ingest())
    assert len(events) == 1
    assert events[0]["eventName"] == "DescribeInstances"
    assert events[0]["eventSource"] == "ec2.amazonaws.com"


def test_ingest_envelope_json_records(tmp_path):
    """Verifies ingestion of standard CloudTrail {"Records": [...]} envelope format."""
    envelope_file = tmp_path / "cloudtrail_envelope.json"
    payload = {
        "Records": [
            {"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com"},
            {"eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com"},
        ]
    }
    envelope_file.write_text(json.dumps(payload), encoding="utf-8")
    
    collector = CloudTrailIngestion(file_path=envelope_file)
    events = list(collector.ingest())
    
    assert len(events) == 2
    assert events[0]["eventName"] == "DescribeInstances"
    assert events[1]["eventName"] == "GetCallerIdentity"


def test_ingest_jsonl_fixture():
    """Verifies streaming ingestion of line-delimited JSON (JSONL)."""
    fixture_path = FIXTURES_DIR / "sample_events.jsonl"
    collector = CloudTrailIngestion(file_path=fixture_path)
    
    events = list(collector.ingest())
    assert len(events) == 3
    assert events[0]["eventName"] == "DescribeInstances"
    assert events[1]["eventName"] == "ConsoleLogin"
    assert events[2]["eventName"] == "CreateAccessKey"


def test_ingest_gzip_json_file(tmp_path):
    """Verifies ingestion of gzip-compressed CloudTrail JSON files (.json.gz)."""
    gz_file = tmp_path / "cloudtrail_archive.json.gz"
    payload = {
        "Records": [
            {"eventName": "PutBucketPolicy", "eventSource": "s3.amazonaws.com"},
            {"eventName": "DeleteBucket", "eventSource": "s3.amazonaws.com"},
        ]
    }
    with gzip.open(gz_file, "wt", encoding="utf-8") as f:
        json.dump(payload, f)
        
    collector = CloudTrailIngestion(file_path=gz_file)
    events = list(collector.ingest())
    
    assert len(events) == 2
    assert events[0]["eventName"] == "PutBucketPolicy"
    assert events[1]["eventName"] == "DeleteBucket"


def test_ingest_directory_recursive(tmp_path):
    """Verifies recursive directory scanning for multiple CloudTrail log files."""
    sub_dir = tmp_path / "2026" / "09"
    sub_dir.mkdir(parents=True)
    
    file1 = sub_dir / "log1.json"
    file1.write_text(json.dumps({"eventName": "Evt1", "eventSource": "iam.amazonaws.com"}), encoding="utf-8")
    
    file2 = sub_dir / "log2.jsonl"
    file2.write_text('{"eventName": "Evt2"}\n{"eventName": "Evt3"}\n', encoding="utf-8")
    
    collector = CloudTrailIngestion(file_path=tmp_path)
    events = list(collector.ingest())
    
    assert len(events) == 3
    event_names = [e["eventName"] for e in events]
    assert "Evt1" in event_names
    assert "Evt2" in event_names
    assert "Evt3" in event_names


def test_ingest_normalized_pipeline():
    """Verifies end-to-end ingest_normalized() generator emitting NormalizedEvent instances."""
    fixture_path = FIXTURES_DIR / "privilege_escalation.json"
    collector = CloudTrailIngestion(file_path=fixture_path)
    
    normalized_events = list(collector.ingest_normalized())
    assert len(normalized_events) == 1
    
    evt = normalized_events[0]
    assert evt.source == TelemetrySource.CLOUDTRAIL
    assert evt.event_name == "AttachUserPolicy"
    assert evt.actor_name == "attacker-charlie"
    assert evt.source_ip == "203.0.113.195"


def test_ingest_s3_read_only_mock():
    """Verifies read-only S3 collection using a mocked boto3 client."""
    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Contents": [{"Key": "AWSLogs/123/CloudTrail/us-east-1/2026/09/27/log.json"}]}
    ]
    
    raw_payload_bytes = json.dumps({
        "Records": [{"eventName": "AuthorizeSecurityGroupIngress", "eventSource": "ec2.amazonaws.com"}]
    }).encode("utf-8")
    
    mock_s3.get_object.return_value = {
        "Body": MagicMock(read=MagicMock(return_value=raw_payload_bytes))
    }
    
    collector = CloudTrailIngestion(
        s3_bucket="test-security-logs-bucket",
        s3_prefix="AWSLogs/",
        s3_client=mock_s3,
    )
    
    events = list(collector.ingest())
    assert len(events) == 1
    assert events[0]["eventName"] == "AuthorizeSecurityGroupIngress"
    mock_s3.get_object.assert_called_once_with(
        Bucket="test-security-logs-bucket",
        Key="AWSLogs/123/CloudTrail/us-east-1/2026/09/27/log.json"
    )

"""
Unit tests for CloudTrailParser and normalization pipeline.
"""

from datetime import datetime, timezone
import pytest
from src.common.constants import TelemetrySource
from src.preprocessing.parser import CloudTrailParser


@pytest.fixture
def parser():
    return CloudTrailParser()


def test_parse_valid_cloudtrail_event(parser, sample_cloudtrail_raw_event):
    """Verifies that a well-formed CloudTrail event parses into NormalizedEvent."""
    normalized = parser.parse(sample_cloudtrail_raw_event)
    
    assert normalized.source == TelemetrySource.CLOUDTRAIL
    assert normalized.event_name == "CreateAccessKey"
    assert normalized.event_source == "iam.amazonaws.com"
    assert normalized.account_id == "123456789012"
    assert normalized.region == "us-east-1"
    assert normalized.actor_arn == "arn:aws:iam::123456789012:user/Alice"
    assert normalized.actor_name == "Alice"
    assert normalized.actor_type == "IAMUser"
    assert normalized.source_ip == "198.51.100.1"
    assert "aws-cli" in normalized.user_agent
    assert isinstance(normalized.timestamp, datetime)
    assert normalized.timestamp.tzinfo is not None


def test_parse_minimal_event_with_missing_fields(parser):
    """Verifies graceful degradation when optional CloudTrail fields are missing."""
    minimal_raw = {
        "eventName": "ListBuckets",
        "eventTime": "2026-09-27T01:30:00Z",
    }
    normalized = parser.parse(minimal_raw)
    
    assert normalized.event_name == "ListBuckets"
    assert normalized.event_source == "unknown.amazonaws.com"
    assert normalized.account_id is None
    assert normalized.actor_arn is None
    assert normalized.source_ip is None
    assert normalized.resources == []


def test_parse_malformed_input_raises_value_error(parser):
    """Verifies that non-dict inputs raise a ValueError."""
    with pytest.raises(ValueError):
        parser.parse(["not", "a", "dict"])  # type: ignore


def test_timestamp_parsing_variations(parser):
    """Verifies that ISO 8601 variations parse into UTC datetimes."""
    # Standard UTC Z
    event_z = {"eventName": "Test", "eventTime": "2026-09-27T10:00:00Z"}
    norm_z = parser.parse(event_z)
    assert norm_z.timestamp == datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)

    # Offset timestamp
    event_offset = {"eventName": "Test", "eventTime": "2026-09-27T15:30:00+05:30"}
    norm_offset = parser.parse(event_offset)
    assert norm_offset.timestamp.tzinfo == timezone.utc

    # Invalid timestamp fallback
    event_invalid = {"eventName": "Test", "eventTime": "invalid-timestamp"}
    norm_invalid = parser.parse(event_invalid)
    assert isinstance(norm_invalid.timestamp, datetime)


def test_sensitive_payload_redaction(parser):
    """Verifies that passwords, tokens, and secret keys are masked in raw payload."""
    raw_with_secrets = {
        "eventName": "CreateUser",
        "requestParameters": {
            "userName": "test-user",
            "password": "SuperSecretPassword123!",
            "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
    }
    normalized = parser.parse(raw_with_secrets)
    
    params = normalized.raw_payload.get("requestParameters", {})
    assert params.get("password") == "[REDACTED]"
    assert params.get("secretAccessKey") == "[REDACTED]"
    assert params.get("userName") == "test-user"

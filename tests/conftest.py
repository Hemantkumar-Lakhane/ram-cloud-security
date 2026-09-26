"""
Pytest configuration and shared test fixtures for RAM Cloud Security.
"""

from datetime import datetime, timezone
import pytest
from src.common.constants import (
    DetectionType,
    FindingSeverity,
    FindingStatus,
    RiskCategory,
    TelemetrySource,
)
from src.common.models import NormalizedEvent, SecurityFinding


@pytest.fixture
def sample_cloudtrail_raw_event():
    """Returns a realistic sample AWS CloudTrail raw JSON record."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEUSER",
            "arn": "arn:aws:iam::123456789012:user/Alice",
            "accountId": "123456789012",
            "userName": "Alice",
        },
        "eventTime": "2026-09-27T00:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.1",
        "userAgent": "aws-cli/2.15.0 Python/3.11.0 Windows/10",
        "requestParameters": {"userName": "Alice"},
        "responseElements": {
            "accessKey": {
                "accessKeyId": "AKIAEXAMPLEKEY",
                "status": "Active",
            }
        },
    }


@pytest.fixture
def sample_normalized_event():
    """Returns a valid NormalizedEvent instance."""
    return NormalizedEvent(
        source=TelemetrySource.CLOUDTRAIL,
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
        account_id="123456789012",
        region="us-east-1",
        actor_arn="arn:aws:iam::123456789012:user/Alice",
        actor_name="Alice",
        actor_type="IAMUser",
        source_ip="198.51.100.1",
        user_agent="aws-cli/2.15.0",
        raw_payload={"sample": "data"},
    )


@pytest.fixture
def sample_security_finding():
    """Returns a valid SecurityFinding instance."""
    return SecurityFinding(
        source=TelemetrySource.CLOUDTRAIL,
        detection_type=DetectionType.RULE,
        severity=FindingSeverity.HIGH,
        confidence=1.0,
        resource="arn:aws:iam::123456789012:user/Alice",
        identity="arn:aws:iam::123456789012:user/Alice",
        title="Excessive Access Key Creation",
        description="IAM User created an access key outside normal working hours.",
        evidence={"event_name": "CreateAccessKey", "source_ip": "198.51.100.1"},
        rule_id="RULE-IAM-001",
        recommended_action="Review and deactivate unused access keys.",
        status=FindingStatus.OPEN,
    )

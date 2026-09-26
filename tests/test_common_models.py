"""
Unit tests for domain models and data contracts.
"""

from uuid import UUID
import pytest
from src.common.constants import (
    DetectionType,
    FindingSeverity,
    FindingStatus,
    RiskCategory,
    TelemetrySource,
)
from src.common.models import (
    NormalizedEvent,
    ResponseActionRecord,
    RiskAssessment,
    SecurityFinding,
)


def test_normalized_event_creation(sample_normalized_event):
    """Verifies that NormalizedEvent initializes and validates properly."""
    assert sample_normalized_event.event_name == "CreateAccessKey"
    assert sample_normalized_event.source == TelemetrySource.CLOUDTRAIL
    assert UUID(sample_normalized_event.event_id)  # Valid UUID format


def test_security_finding_contract(sample_security_finding):
    """Verifies that SecurityFinding satisfies the universal schema."""
    assert sample_security_finding.severity == FindingSeverity.HIGH
    assert sample_security_finding.detection_type == DetectionType.RULE
    assert sample_security_finding.confidence == 1.0
    assert sample_security_finding.rule_id == "RULE-IAM-001"
    assert sample_security_finding.status == FindingStatus.OPEN
    assert UUID(sample_security_finding.finding_id)


def test_risk_assessment_model():
    """Verifies risk assessment model scoring constraints."""
    assessment = RiskAssessment(
        finding_id="test-finding-123",
        identity_criticality=0.9,
        asset_criticality=0.8,
        vulnerability_score=0.5,
        composite_risk_score=85.0,
        risk_category=RiskCategory.HIGH_RISK,
        rationale="High privilege identity performing sensitive action on critical asset.",
    )
    assert assessment.composite_risk_score == 85.0
    assert assessment.risk_category == RiskCategory.HIGH_RISK


def test_response_action_record_defaults():
    """Verifies that response actions default to dry_run = True for safety."""
    record = ResponseActionRecord(
        finding_id="test-finding-123",
        action_type="QUARANTINE_ROLE",
        target_resource="arn:aws:iam::123456789012:role/CompromisedRole",
    )
    assert record.dry_run is True
    assert record.executed is False

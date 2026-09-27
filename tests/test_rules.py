"""
Unit tests for deterministic security rules (IAM, Configuration, Exposure).
"""

import pytest
from src.common.constants import DetectionType, FindingSeverity, FindingStatus, TelemetrySource
from src.common.models import NormalizedEvent
from src.detection.rules.configuration_rules import (
    BucketPolicyDeletionRule,
    CloudTrailTamperingRule,
    FlowLogsTamperingRule,
    SecretOrKeyDeletionRule,
)
from src.detection.rules.engine import RuleEngine
from src.detection.rules.exposure_rules import (
    OpenSecurityGroupIngressRule,
    S3BucketPublicPolicyRule,
    SecurityGroupEgressRevocationRule,
)
from src.detection.rules.iam_rules import (
    AccessKeyCreationRule,
    AdminPolicyAttachmentRule,
    AssumeRolePolicyUpdateRule,
    ConsoleLoginProfileRule,
    InlinePolicyInjectionRule,
)


def create_event(
    event_name: str,
    event_source: str,
    raw_params: dict = None,
    actor_name: str = "test-actor",
    actor_arn: str = "arn:aws:iam::123456789012:user/test-actor",
) -> NormalizedEvent:
    return NormalizedEvent(
        source=TelemetrySource.CLOUDTRAIL,
        event_name=event_name,
        event_source=event_source,
        account_id="123456789012",
        region="us-east-1",
        actor_name=actor_name,
        actor_arn=actor_arn,
        raw_payload={"requestParameters": raw_params or {}},
    )


def test_admin_policy_attachment_rule():
    rule = AdminPolicyAttachmentRule()
    # Matching event
    event_match = create_event(
        "AttachUserPolicy",
        "iam.amazonaws.com",
        {"userName": "dev", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    finding = rule.evaluate(event_match)
    assert finding is not None
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.rule_id == "RULE-IAM-001"
    assert "AdministratorAccess" in finding.evidence["policy_arn"]

    # Non-matching event
    event_benign = create_event(
        "AttachUserPolicy",
        "iam.amazonaws.com",
        {"userName": "dev", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )
    assert rule.evaluate(event_benign) is None


def test_inline_policy_injection_rule():
    rule = InlinePolicyInjectionRule()
    event_wildcard = create_event(
        "PutUserPolicy",
        "iam.amazonaws.com",
        {"userName": "dev", "policyName": "CustomInline", "policyDocument": '{"Action":"*","Resource":"*"}'},
    )
    finding = rule.evaluate(event_wildcard)
    assert finding is not None
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.rule_id == "RULE-IAM-002"


def test_access_key_creation_rule():
    rule = AccessKeyCreationRule()
    event = create_event(
        "CreateAccessKey",
        "iam.amazonaws.com",
        {"userName": "target-user"},
        actor_name="creator-user",
    )
    finding = rule.evaluate(event)
    assert finding is not None
    assert finding.severity == FindingSeverity.HIGH
    assert finding.evidence["is_different_principal"] is True


def test_cloudtrail_tampering_rule():
    rule = CloudTrailTamperingRule()
    event_stop = create_event(
        "StopLogging",
        "cloudtrail.amazonaws.com",
        {"name": "production-trail"},
    )
    finding = rule.evaluate(event_stop)
    assert finding is not None
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.evidence["action"] == "StopLogging"


def test_flow_logs_tampering_rule():
    rule = FlowLogsTamperingRule()
    event_del = create_event(
        "DeleteFlowLogs",
        "ec2.amazonaws.com",
        {"flowLogIdSet": ["fl-12345678"]},
    )
    finding = rule.evaluate(event_del)
    assert finding is not None
    assert finding.rule_id == "RULE-CFG-002"


def test_open_security_group_ingress_rule():
    rule = OpenSecurityGroupIngressRule()
    event_open = create_event(
        "AuthorizeSecurityGroupIngress",
        "ec2.amazonaws.com",
        {"groupId": "sg-123", "cidrIp": "0.0.0.0/0", "fromPort": 22, "toPort": 22},
    )
    finding = rule.evaluate(event_open)
    assert finding is not None
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.evidence["cidr"] == "0.0.0.0/0"


def test_rule_engine_stream_evaluation():
    engine = RuleEngine()
    events = [
        create_event("DescribeInstances", "ec2.amazonaws.com"),  # Benign
        create_event("StopLogging", "cloudtrail.amazonaws.com", {"name": "main-trail"}),  # Trigger CFG-001
        create_event("CreateLoginProfile", "iam.amazonaws.com", {"userName": "backdoor"}),  # Trigger IAM-004
    ]
    findings = engine.evaluate_stream(events)
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-CFG-001" in rule_ids
    assert "RULE-IAM-004" in rule_ids

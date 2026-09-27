"""
Deterministic Rule Engine for RAM Cloud Security.
Registers detection rules and executes evaluations against NormalizedEvent streams.
"""

from typing import List, Optional
from src.common.logger import get_logger
from src.common.models import NormalizedEvent, SecurityFinding
from src.detection.rules.base import BaseDetectionRule
from src.detection.rules.configuration_rules import (
    BucketPolicyDeletionRule,
    CloudTrailTamperingRule,
    FlowLogsTamperingRule,
    SecretOrKeyDeletionRule,
)
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

logger = get_logger(__name__)


class RuleEngine:
    """
    Executes a registry of deterministic security rules against incoming normalized events.
    """

    def __init__(self, rules: Optional[List[BaseDetectionRule]] = None):
        """
        Initializes the rule engine with default or custom rules.
        """
        if rules is not None:
            self.rules = rules
        else:
            self.rules = self._get_default_rules()

    def _get_default_rules(self) -> List[BaseDetectionRule]:
        """Returns the standard default registry of deterministic detection rules."""
        return [
            # IAM Rules
            AdminPolicyAttachmentRule(),
            InlinePolicyInjectionRule(),
            AccessKeyCreationRule(),
            ConsoleLoginProfileRule(),
            AssumeRolePolicyUpdateRule(),
            # Configuration Rules
            CloudTrailTamperingRule(),
            FlowLogsTamperingRule(),
            BucketPolicyDeletionRule(),
            SecretOrKeyDeletionRule(),
            # Exposure Rules
            OpenSecurityGroupIngressRule(),
            SecurityGroupEgressRevocationRule(),
            S3BucketPublicPolicyRule(),
        ]

    def evaluate_event(self, event: NormalizedEvent) -> List[SecurityFinding]:
        """
        Evaluates a single event against all registered rules and collects findings.
        """
        findings: List[SecurityFinding] = []
        for rule in self.rules:
            try:
                finding = rule.evaluate(event)
                if finding is not None:
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id} on event {event.event_id}: {e}")
        return findings

    def evaluate_stream(self, events: List[NormalizedEvent]) -> List[SecurityFinding]:
        """
        Evaluates a collection of normalized events and returns all triggered findings.
        """
        all_findings: List[SecurityFinding] = []
        for event in events:
            all_findings.extend(self.evaluate_event(event))
        return all_findings

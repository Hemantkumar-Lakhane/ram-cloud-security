"""
Deterministic security rules module for RAM Cloud Security.
"""

from src.detection.rules.base import BaseDetectionRule
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

__all__ = [
    "BaseDetectionRule",
    "RuleEngine",
    # IAM Rules
    "AdminPolicyAttachmentRule",
    "InlinePolicyInjectionRule",
    "AccessKeyCreationRule",
    "ConsoleLoginProfileRule",
    "AssumeRolePolicyUpdateRule",
    # Configuration Rules
    "CloudTrailTamperingRule",
    "FlowLogsTamperingRule",
    "BucketPolicyDeletionRule",
    "SecretOrKeyDeletionRule",
    # Exposure Rules
    "OpenSecurityGroupIngressRule",
    "SecurityGroupEgressRevocationRule",
    "S3BucketPublicPolicyRule",
]

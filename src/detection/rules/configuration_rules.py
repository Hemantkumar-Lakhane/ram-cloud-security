"""
Deterministic detection rules for cloud configuration tampering and defense evasion.
"""

from typing import Optional
from src.common.constants import FindingSeverity
from src.common.models import NormalizedEvent, SecurityFinding
from src.detection.rules.base import BaseDetectionRule


class CloudTrailTamperingRule(BaseDetectionRule):
    """
    CFG-001: Detects disabling or deletion of AWS CloudTrail logging.
    MITRE ATT&CK: T1562.001 - Impair Defenses: Disable Cloud Logs
    """
    rule_id = "RULE-CFG-001"
    name = "CloudTrail Logging Disabled or Deleted"
    description = "Detects attempts to stop logging or delete AWS CloudTrail audit trails."
    severity = FindingSeverity.CRITICAL
    confidence = 1.0
    mitre_technique_id = "T1562.001"
    mitre_tactic = "Defense Evasion"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "cloudtrail.amazonaws.com":
            return None

        if event.event_name in ["StopLogging", "DeleteTrail"]:
            params = event.raw_payload.get("requestParameters") or {}
            trail_name = params.get("name", "unknown")

            return self.create_finding(
                event=event,
                title=f"CloudTrail Audit Logging {event.event_name}",
                description=f"Auditing defense impaired: '{event.event_name}' executed on trail '{trail_name}'.",
                evidence={
                    "action": event.event_name,
                    "trail_name": trail_name,
                },
                severity=FindingSeverity.CRITICAL,
                recommended_action="Immediately re-enable CloudTrail logging and investigate actor credentials.",
            )
        return None


class FlowLogsTamperingRule(BaseDetectionRule):
    """
    CFG-002: Detects deletion of VPC Flow Logs.
    MITRE ATT&CK: T1562.001 - Impair Defenses: Disable Network Monitoring
    """
    rule_id = "RULE-CFG-002"
    name = "VPC Flow Logs Deleted"
    description = "Detects deletion of VPC Flow Logs disabling network traffic auditing."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1562.001"
    mitre_tactic = "Defense Evasion"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "ec2.amazonaws.com":
            return None

        if event.event_name == "DeleteFlowLogs":
            params = event.raw_payload.get("requestParameters") or {}
            flow_log_ids = params.get("flowLogIdSet", {})

            return self.create_finding(
                event=event,
                title="VPC Flow Logs Deletion",
                description="Network audit telemetry impaired: DeleteFlowLogs executed on VPC.",
                evidence={
                    "flow_log_ids": flow_log_ids,
                },
                severity=FindingSeverity.HIGH,
                recommended_action="Verify if VPC Flow Log deletion was authorized and restore flow logging.",
            )
        return None


class BucketPolicyDeletionRule(BaseDetectionRule):
    """
    CFG-003: Detects deletion of S3 bucket security policies.
    MITRE ATT&CK: T1562.001 - Impair Defenses
    """
    rule_id = "RULE-CFG-003"
    name = "S3 Bucket Policy Deleted"
    description = "Detects removal of an S3 bucket policy which may remove security constraints or access restrictions."
    severity = FindingSeverity.HIGH
    confidence = 0.9
    mitre_technique_id = "T1562.001"
    mitre_tactic = "Defense Evasion"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "s3.amazonaws.com":
            return None

        if event.event_name in ["DeleteBucketPolicy", "DeleteBucketPublicAccessBlockConfiguration"]:
            params = event.raw_payload.get("requestParameters") or {}
            bucket_name = params.get("bucketName", "unknown")

            return self.create_finding(
                event=event,
                title=f"S3 Security Configuration Removed ({event.event_name})",
                description=f"Security boundaries altered: {event.event_name} executed on bucket '{bucket_name}'.",
                evidence={
                    "bucket_name": bucket_name,
                    "action": event.event_name,
                },
                severity=FindingSeverity.HIGH,
                recommended_action="Re-apply bucket access controls and verify S3 block public access settings.",
            )
        return None


class SecretOrKeyDeletionRule(BaseDetectionRule):
    """
    CFG-004: Detects deletion of Secrets Manager secrets or disabling KMS keys.
    MITRE ATT&CK: T1486 - Data Encrypted for Impact / T1562.001
    """
    rule_id = "RULE-CFG-004"
    name = "KMS Key or Secret Deletion / Disabling"
    description = "Detects attempts to delete secrets or disable cryptographic keys."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1486"
    mitre_tactic = "Impact"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source == "secretsmanager.amazonaws.com" and event.event_name == "DeleteSecret":
            params = event.raw_payload.get("requestParameters") or {}
            secret_id = params.get("secretId", "unknown")
            return self.create_finding(
                event=event,
                title="Secret Deletion Scheduled",
                description=f"SecretsManager secret '{secret_id}' scheduled for deletion.",
                evidence={"secret_id": secret_id},
                severity=FindingSeverity.HIGH,
                recommended_action="Review whether secret deletion was planned; restore secret from recovery window if needed.",
            )

        if event.event_source == "kms.amazonaws.com" and event.event_name in ["ScheduleKeyDeletion", "DisableKey"]:
            params = event.raw_payload.get("requestParameters") or {}
            key_id = params.get("keyId", "unknown")
            return self.create_finding(
                event=event,
                title=f"KMS Key {event.event_name}",
                description=f"Cryptographic key '{key_id}' altered via {event.event_name}.",
                evidence={"key_id": key_id, "action": event.event_name},
                severity=FindingSeverity.HIGH,
                recommended_action="Verify KMS key lifecycle change to avoid unintended service encryption outages.",
            )
        return None

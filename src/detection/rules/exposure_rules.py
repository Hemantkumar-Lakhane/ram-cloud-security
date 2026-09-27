"""
Deterministic detection rules for cloud exposure and network boundary tampering.
"""

from typing import Optional
from src.common.constants import FindingSeverity
from src.common.models import NormalizedEvent, SecurityFinding
from src.detection.rules.base import BaseDetectionRule


class OpenSecurityGroupIngressRule(BaseDetectionRule):
    """
    EXP-001: Detects opening security group ingress to the entire internet (0.0.0.0/0).
    MITRE ATT&CK: T1046 - Network Service Discovery / T1133 - External Remote Services
    """
    rule_id = "RULE-EXP-001"
    name = "Unrestricted Security Group Ingress Allowed (0.0.0.0/0)"
    description = "Detects security group rules granting inbound access from any IP address on the internet."
    severity = FindingSeverity.HIGH
    confidence = 1.0
    mitre_technique_id = "T1133"
    mitre_tactic = "Initial Access"

    SENSITIVE_PORTS = {22, 3389, 80, 443, 3306, 5432, 27017, 6379, 8080, 8443, 9200}

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "ec2.amazonaws.com":
            return None

        if event.event_name == "AuthorizeSecurityGroupIngress":
            params = event.raw_payload.get("requestParameters") or {}
            group_id = params.get("groupId", "unknown")
            ip_permissions = params.get("ipPermissions", {})
            
            # Check for 0.0.0.0/0 in request payload
            raw_str = str(params)
            is_open_cidr = "0.0.0.0/0" in raw_str or "::/0" in raw_str
            
            if is_open_cidr:
                return self.create_finding(
                    event=event,
                    title="Security Group Ingress Opened to Internet (0.0.0.0/0)",
                    description=f"Security Group '{group_id}' authorized unrestricted ingress from 0.0.0.0/0.",
                    evidence={
                        "group_id": group_id,
                        "cidr": "0.0.0.0/0",
                        "request_parameters": params,
                    },
                    severity=FindingSeverity.CRITICAL,
                    recommended_action="Restrict ingress to authorized corporate CIDR blocks or bastion hosts.",
                )
        return None


class SecurityGroupEgressRevocationRule(BaseDetectionRule):
    """
    EXP-002: Detects revocation of security group egress rules.
    MITRE ATT&CK: T1562 - Impair Defenses
    """
    rule_id = "RULE-EXP-002"
    name = "Security Group Egress Rule Revoked"
    description = "Detects modifications that alter outbound network boundary controls."
    severity = FindingSeverity.MEDIUM
    confidence = 0.9
    mitre_technique_id = "T1562"
    mitre_tactic = "Defense Evasion"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "ec2.amazonaws.com":
            return None

        if event.event_name == "RevokeSecurityGroupEgress":
            params = event.raw_payload.get("requestParameters") or {}
            group_id = params.get("groupId", "unknown")

            return self.create_finding(
                event=event,
                title="Security Group Egress Boundary Modified",
                description=f"Outbound traffic rules revoked on Security Group '{group_id}'.",
                evidence={"group_id": group_id},
                severity=FindingSeverity.MEDIUM,
                recommended_action="Confirm that outbound traffic rule modifications align with network architecture.",
            )
        return None


class S3BucketPublicPolicyRule(BaseDetectionRule):
    """
    EXP-003: Detects S3 bucket policies or ACLs granting public exposure.
    MITRE ATT&CK: T1530 - Data from Cloud Storage Object
    """
    rule_id = "RULE-EXP-003"
    name = "S3 Bucket Public Policy Applied"
    description = "Detects bucket policy applications that contain wildcard principals (*)."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1530"
    mitre_tactic = "Exfiltration"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "s3.amazonaws.com":
            return None

        if event.event_name in ["PutBucketPolicy", "PutBucketAcl"]:
            params = event.raw_payload.get("requestParameters") or {}
            bucket_name = params.get("bucketName", "unknown")
            policy_str = str(params)

            is_wildcard = '"Principal":"*"' in policy_str or '"Principal": "*"' in policy_str or '"AWS":"*"' in policy_str

            if is_wildcard:
                return self.create_finding(
                    event=event,
                    title="S3 Bucket Policy Grants Public Access (*)",
                    description=f"Bucket '{bucket_name}' policy contains wildcard principal (*), potentially exposing data publicly.",
                    evidence={
                        "bucket_name": bucket_name,
                        "wildcard_detected": True,
                    },
                    severity=FindingSeverity.CRITICAL,
                    recommended_action="Remove wildcard principal from bucket policy and enforce S3 Block Public Access.",
                )
        return None

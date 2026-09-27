"""
Deterministic detection rules for AWS IAM identity and privilege operations.
"""

from typing import Optional
from src.common.constants import FindingSeverity
from src.common.models import NormalizedEvent, SecurityFinding
from src.detection.rules.base import BaseDetectionRule


class AdminPolicyAttachmentRule(BaseDetectionRule):
    """
    IAM-001: Detects attachment of AdministratorAccess or wildcard administrative policies.
    MITRE ATT&CK: T1098 - Account Manipulation / Privilege Escalation
    """
    rule_id = "RULE-IAM-001"
    name = "Administrator Policy Attached to Principal"
    description = "Detects attachment of full AdministratorAccess policy to a user, role, or group."
    severity = FindingSeverity.CRITICAL
    confidence = 1.0
    mitre_technique_id = "T1098"
    mitre_tactic = "Privilege Escalation"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "iam.amazonaws.com":
            return None

        if event.event_name in ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"]:
            params = event.raw_payload.get("requestParameters") or {}
            policy_arn = str(params.get("policyArn", ""))
            
            if "AdministratorAccess" in policy_arn or "policy/admin" in policy_arn.lower():
                return self.create_finding(
                    event=event,
                    title="Administrative Policy Attached",
                    description=f"Principal attached '{policy_arn}' granting full administrative privileges.",
                    evidence={
                        "policy_arn": policy_arn,
                        "target_entity": params.get("userName") or params.get("roleName") or params.get("groupName"),
                    },
                    recommended_action="Validate principal authorization and revoke administrative policy if unauthorized.",
                )
        return None


class InlinePolicyInjectionRule(BaseDetectionRule):
    """
    IAM-002: Detects inline policy creation/modification on IAM entities.
    MITRE ATT&CK: T1098.001 - Additional Cloud Roles / Policies
    """
    rule_id = "RULE-IAM-002"
    name = "Inline IAM Policy Injection"
    description = "Detects creation or update of inline IAM policies which may bypass centralized policy controls."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1098.001"
    mitre_tactic = "Privilege Escalation"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "iam.amazonaws.com":
            return None

        if event.event_name in ["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"]:
            params = event.raw_payload.get("requestParameters") or {}
            policy_name = params.get("policyName", "unknown")
            policy_doc = str(params.get("policyDocument", ""))
            
            # Check for overly broad wildcard grants
            is_wildcard = '"*"' in policy_doc or "'*'" in policy_doc
            
            return self.create_finding(
                event=event,
                title="Inline IAM Policy Created or Modified",
                description=f"Inline policy '{policy_name}' was put on an IAM principal." + (" (Wildcard detected)" if is_wildcard else ""),
                evidence={
                    "policy_name": policy_name,
                    "target_entity": params.get("userName") or params.get("roleName") or params.get("groupName"),
                    "has_wildcard": is_wildcard,
                },
                severity=FindingSeverity.CRITICAL if is_wildcard else FindingSeverity.HIGH,
                recommended_action="Review inline policy permissions and migrate to version-controlled managed policies.",
            )
        return None


class AccessKeyCreationRule(BaseDetectionRule):
    """
    IAM-003: Detects access key creation for IAM users.
    MITRE ATT&CK: T1098 - Account Manipulation / Persistence
    """
    rule_id = "RULE-IAM-003"
    name = "IAM Access Key Created"
    description = "Detects generation of programmatic access keys for IAM users."
    severity = FindingSeverity.MEDIUM
    confidence = 0.9
    mitre_technique_id = "T1098"
    mitre_tactic = "Persistence"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "iam.amazonaws.com":
            return None

        if event.event_name == "CreateAccessKey":
            params = event.raw_payload.get("requestParameters") or {}
            target_user = params.get("userName", event.actor_name)
            is_different_user = target_user != event.actor_name if target_user and event.actor_name else False

            return self.create_finding(
                event=event,
                title="New IAM Access Key Generated",
                description=f"Access key created for user '{target_user}'" + (" by another principal." if is_different_user else "."),
                evidence={
                    "target_user": target_user,
                    "created_by": event.actor_name,
                    "is_different_principal": is_different_user,
                },
                severity=FindingSeverity.HIGH if is_different_user else FindingSeverity.MEDIUM,
                recommended_action="Verify business justification for programmatic access keys and enforce MFA.",
            )
        return None


class ConsoleLoginProfileRule(BaseDetectionRule):
    """
    IAM-004: Detects creation of console login profiles (enabling password/web access).
    MITRE ATT&CK: T1136.003 - Cloud Account Creation / Persistence
    """
    rule_id = "RULE-IAM-004"
    name = "Console Login Profile Created"
    description = "Detects creation of a console login password for an existing IAM user."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1136.003"
    mitre_tactic = "Persistence"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "iam.amazonaws.com":
            return None

        if event.event_name == "CreateLoginProfile":
            params = event.raw_payload.get("requestParameters") or {}
            target_user = params.get("userName", "unknown")

            return self.create_finding(
                event=event,
                title="Console Password Login Enabled",
                description=f"Web console login password was created for user '{target_user}'.",
                evidence={
                    "target_user": target_user,
                    "password_reset_required": params.get("passwordResetRequired", False),
                },
                recommended_action="Ensure console users require mandatory MFA and conform to least-privilege access.",
            )
        return None


class AssumeRolePolicyUpdateRule(BaseDetectionRule):
    """
    IAM-005: Detects modification of AssumeRole trust policy (backdoor/cross-account access).
    MITRE ATT&CK: T1098 - Account Manipulation / Defense Evasion
    """
    rule_id = "RULE-IAM-005"
    name = "IAM Role Trust Policy Modified"
    description = "Detects alterations to IAM role trust relationships which may allow cross-account access."
    severity = FindingSeverity.HIGH
    confidence = 0.95
    mitre_technique_id = "T1098"
    mitre_tactic = "Persistence"

    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        if event.event_source != "iam.amazonaws.com":
            return None

        if event.event_name == "UpdateAssumeRolePolicy":
            params = event.raw_payload.get("requestParameters") or {}
            role_name = params.get("roleName", "unknown")
            policy_doc = str(params.get("policyDocument", ""))
            
            is_wildcard = '"*"' in policy_doc or "'*'" in policy_doc

            return self.create_finding(
                event=event,
                title="IAM Role Trust Relationship Altered",
                description=f"Trust policy for role '{role_name}' was modified." + (" (Wildcard Principal detected)" if is_wildcard else ""),
                evidence={
                    "role_name": role_name,
                    "has_wildcard": is_wildcard,
                },
                severity=FindingSeverity.CRITICAL if is_wildcard else FindingSeverity.HIGH,
                recommended_action="Audit role trust policy for unauthorized external principals or open wildcards.",
            )
        return None

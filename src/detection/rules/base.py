"""
Base interfaces for deterministic detection rules.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from src.common.constants import DetectionType, FindingSeverity, FindingStatus, TelemetrySource
from src.common.models import NormalizedEvent, SecurityFinding


class BaseDetectionRule(ABC):
    """
    Abstract base class for all deterministic security rules.
    """
    rule_id: str
    name: str
    description: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: float = 1.0
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None

    @abstractmethod
    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        """
        Evaluates an individual event and returns a SecurityFinding if violated, or None.
        """
        pass

    def create_finding(
        self,
        event: NormalizedEvent,
        title: str,
        description: str,
        evidence: Dict,
        recommended_action: Optional[str] = None,
        severity: Optional[FindingSeverity] = None,
        confidence: Optional[float] = None,
    ) -> SecurityFinding:
        """
        Helper method to construct a standard SecurityFinding instance.
        """
        resource_target = event.resources[0].get("arn") if event.resources else (event.actor_arn or "AWS-Resource")
        identity_target = event.actor_arn or event.actor_name or "UnknownPrincipal"
        
        return SecurityFinding(
            source=event.source,
            detection_type=DetectionType.RULE,
            severity=severity or self.severity,
            confidence=confidence if confidence is not None else self.confidence,
            resource=str(resource_target),
            identity=str(identity_target),
            title=title,
            description=description,
            evidence={
                "event_id": event.event_id,
                "event_name": event.event_name,
                "event_source": event.event_source,
                "timestamp": event.timestamp.isoformat(),
                "mitre_technique_id": self.mitre_technique_id,
                "mitre_tactic": self.mitre_tactic,
                **evidence,
            },
            rule_id=self.rule_id,
            recommended_action=recommended_action,
            status=FindingStatus.OPEN,
        )

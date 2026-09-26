"""
Domain models and standardized data contracts for RAM Cloud Security.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from src.common.constants import (
    DetectionType,
    FindingSeverity,
    FindingStatus,
    RiskCategory,
    TelemetrySource,
)


class NormalizedEvent(BaseModel):
    """
    OCSF-compatible normalized cloud security event representation.
    Serves as the universal intermediate format for both Rule Engine and ML Feature Extraction.
    """
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: TelemetrySource
    event_name: str
    event_source: str
    account_id: Optional[str] = None
    region: Optional[str] = None

    # Identity Context
    actor_arn: Optional[str] = None
    actor_name: Optional[str] = None
    actor_type: Optional[str] = None
    session_issuer_arn: Optional[str] = None

    # Network / Client Context
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None

    # Outcome / Status
    status_code: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    # Resource Context
    resources: List[Dict[str, Any]] = Field(default_factory=list)

    # Raw Payload Storage
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    """
    Universal Security Finding contract.
    Both the deterministic Rule Engine and probabilistic ML Engine emit findings in this format.
    """
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: TelemetrySource
    detection_type: DetectionType
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    
    # Target Attribution
    resource: str
    identity: str
    
    # Details & Explanation
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    
    # Engine References
    rule_id: Optional[str] = None
    model_version: Optional[str] = None
    anomaly_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    contributing_features: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Operational Lifecycle
    recommended_action: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN


class RiskAssessment(BaseModel):
    """
    Contextualized Risk Assessment combining findings with asset and identity criticality.
    """
    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Context Multipliers
    identity_criticality: float = Field(ge=0.0, le=1.0, default=0.5)
    asset_criticality: float = Field(ge=0.0, le=1.0, default=0.5)
    vulnerability_score: float = Field(ge=0.0, le=1.0, default=0.0)
    
    # Calculated Risk
    composite_risk_score: float = Field(ge=0.0, le=100.0)
    risk_category: RiskCategory
    rationale: str


class ResponseActionRecord(BaseModel):
    """
    Audit record for automated or human-approved response actions.
    """
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action_type: str
    target_resource: str
    dry_run: bool = True
    executed: bool = False
    approved_by: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)

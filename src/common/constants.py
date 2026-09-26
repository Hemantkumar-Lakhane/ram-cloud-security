"""
Shared constants and enumerations for RAM Cloud Security.
"""

from enum import Enum


class DetectionType(str, Enum):
    RULE = "RULE"
    ML_ANOMALY = "ML_ANOMALY"
    HYBRID = "HYBRID"


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class RiskCategory(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH-RISK"


class TelemetrySource(str, Enum):
    CLOUDTRAIL = "CLOUDTRAIL"
    VPC_FLOW = "VPC_FLOW"
    AWS_CONFIG = "AWS_CONFIG"
    INSPECTOR = "INSPECTOR"
    CLOUDWATCH = "CLOUDWATCH"

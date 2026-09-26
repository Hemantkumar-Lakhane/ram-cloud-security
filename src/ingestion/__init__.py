"""
Telemetry Ingestion module for RAM Cloud Security.
"""

from src.ingestion.base import BaseTelemetryIngestion
from src.ingestion.cloudtrail import CloudTrailIngestion

__all__ = ["BaseTelemetryIngestion", "CloudTrailIngestion"]

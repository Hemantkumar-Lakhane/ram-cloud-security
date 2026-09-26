"""
Base interfaces for security context enrichment and risk prioritization.
"""

from abc import ABC, abstractmethod
from typing import List
from src.common.models import RiskAssessment, SecurityFinding


class BaseRiskPrioritizer(ABC):
    """
    Abstract base class for risk evaluation and finding prioritization.
    """

    @abstractmethod
    def evaluate_risk(self, finding: SecurityFinding) -> RiskAssessment:
        """
        Calculates composite contextual risk score for a given security finding.
        """
        pass

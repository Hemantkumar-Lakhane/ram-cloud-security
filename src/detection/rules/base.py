"""
Base interfaces for deterministic detection rules.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from src.common.models import NormalizedEvent, SecurityFinding


class BaseDetectionRule(ABC):
    """
    Abstract base class for all deterministic security rules.
    """
    rule_id: str
    name: str
    description: str

    @abstractmethod
    def evaluate(self, event: NormalizedEvent) -> Optional[SecurityFinding]:
        """
        Evaluates an individual event and returns a SecurityFinding if violated, or None.
        """
        pass

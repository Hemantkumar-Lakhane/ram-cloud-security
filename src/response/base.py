"""
Base interfaces for controlled response orchestration.
"""

from abc import ABC, abstractmethod
from typing import Optional
from src.common.models import ResponseActionRecord, SecurityFinding


class BaseResponseOrchestrator(ABC):
    """
    Abstract base class for executing safe and audited response actions.
    """

    @abstractmethod
    def plan_response(self, finding: SecurityFinding) -> ResponseActionRecord:
        """
        Creates a planned response action record with default dry_run = True.
        """
        pass

    @abstractmethod
    def execute_response(
        self, action: ResponseActionRecord, confirmed_by: Optional[str] = None
    ) -> ResponseActionRecord:
        """
        Executes the planned response action if safe mode and human approvals are satisfied.
        """
        pass

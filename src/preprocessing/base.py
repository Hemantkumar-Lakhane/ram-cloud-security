"""
Base interfaces for parsing and normalizing raw telemetry into NormalizedEvents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from src.common.models import NormalizedEvent


class BaseEventParser(ABC):
    """
    Abstract base class for service-specific telemetry parsers.
    """

    @abstractmethod
    def parse(self, raw_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Parses a raw event dictionary into a validated NormalizedEvent model.
        """
        pass

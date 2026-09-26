"""
Base interface for telemetry ingestion sources.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator


class BaseTelemetryIngestion(ABC):
    """
    Abstract base class for all telemetry collectors (CloudTrail, VPC Flow, Config, Inspector).
    """

    @abstractmethod
    def ingest(self) -> Iterator[Dict[str, Any]]:
        """
        Yields raw telemetry event dictionaries.
        """
        pass

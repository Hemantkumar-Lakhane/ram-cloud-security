"""
Base interface for security feature extractors.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
import pandas as pd
from src.common.models import NormalizedEvent


class BaseFeatureExtractor(ABC):
    """
    Abstract base class for extracting statistical and behavioral features from NormalizedEvents.
    """

    @abstractmethod
    def extract_features(self, events: List[NormalizedEvent]) -> pd.DataFrame:
        """
        Transforms a sequence of normalized events into a feature matrix DataFrame.
        """
        pass

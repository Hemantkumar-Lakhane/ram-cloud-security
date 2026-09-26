"""
Base interfaces for Machine Learning anomaly and threat detection models.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
import pandas as pd
from src.common.models import SecurityFinding


class BaseAnomalyDetector(ABC):
    """
    Abstract base class for ML anomaly detection algorithms.
    """
    model_name: str
    model_version: str

    @abstractmethod
    def fit(self, features: pd.DataFrame) -> "BaseAnomalyDetector":
        """
        Fits the anomaly detection model to baseline features.
        """
        pass

    @abstractmethod
    def predict_anomaly_scores(self, features: pd.DataFrame) -> pd.Series:
        """
        Generates normalized anomaly scores [0.0 - 1.0] for feature records.
        """
        pass

    @abstractmethod
    def generate_findings(
        self, features: pd.DataFrame, threshold: float
    ) -> List[SecurityFinding]:
        """
        Evaluates features and emits explainable SecurityFinding instances for anomalies.
        """
        pass

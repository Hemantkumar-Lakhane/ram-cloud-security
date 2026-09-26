"""
Unit tests validating architecture scaffolding and package imports.
"""

from src.common.config import get_config
from src.ingestion.base import BaseTelemetryIngestion
from src.preprocessing.base import BaseEventParser
from src.features.base import BaseFeatureExtractor
from src.detection.rules.base import BaseDetectionRule
from src.detection.ml.base import BaseAnomalyDetector
from src.risk.base import BaseRiskPrioritizer
from src.response.base import BaseResponseOrchestrator


def test_package_scaffolding_and_interfaces():
    """Validates that all architectural layer interfaces are properly accessible."""
    assert BaseTelemetryIngestion is not None
    assert BaseEventParser is not None
    assert BaseFeatureExtractor is not None
    assert BaseDetectionRule is not None
    assert BaseAnomalyDetector is not None
    assert BaseRiskPrioritizer is not None
    assert BaseResponseOrchestrator is not None


def test_app_config_singleton():
    """Validates configuration loader and safety defaults."""
    config = get_config()
    assert config is not None
    assert config.dry_run is True
    assert config.safe_mode is True
    assert config.automated_response_enabled is False

"""
Application settings and configuration manager.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AppConfig:
    """Central configuration for RAM Cloud Security."""
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")

    # AWS
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    aws_profile: Optional[str] = field(default_factory=lambda: os.getenv("AWS_PROFILE", None))

    # Storage
    data_lake_bucket: str = field(
        default_factory=lambda: os.getenv("SECURITY_DATA_LAKE_BUCKET", "ram-cloud-security-data-lake")
    )
    data_local_dir: Path = field(
        default_factory=lambda: Path(os.getenv("SECURITY_DATA_LOCAL_DIR", "./data"))
    )

    # Ingestion
    cloudtrail_source: str = field(
        default_factory=lambda: os.getenv("CLOUDTRAIL_INGESTION_SOURCE", "local")
    )
    poll_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("CLOUDTRAIL_POLL_INTERVAL_SECONDS", "60"))
    )

    # Detection & Risk
    ml_anomaly_threshold: float = field(
        default_factory=lambda: float(os.getenv("ML_ANOMALY_THRESHOLD", "0.75"))
    )
    risk_score_high_threshold: int = field(
        default_factory=lambda: int(os.getenv("RISK_SCORE_HIGH_THRESHOLD", "80"))
    )
    risk_score_medium_threshold: int = field(
        default_factory=lambda: int(os.getenv("RISK_SCORE_MEDIUM_THRESHOLD", "50"))
    )

    # Safety Guardrails
    automated_response_enabled: bool = field(
        default_factory=lambda: os.getenv("AUTOMATED_RESPONSE_ENABLED", "false").lower() == "true"
    )
    safe_mode: bool = field(
        default_factory=lambda: os.getenv("SAFE_MODE", "true").lower() == "true"
    )
    dry_run: bool = field(
        default_factory=lambda: os.getenv("DRY_RUN", "true").lower() == "true"
    )


_config_instance: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Returns singleton configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = AppConfig()
    return _config_instance

"""
Logging configuration for RAM Cloud Security.
"""

import logging
import os
import sys


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger instance with standardized formatting.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

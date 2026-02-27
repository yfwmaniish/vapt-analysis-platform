"""Structured logging utility for the scan engine."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone


def get_logger(name: str = "vaptx") -> logging.Logger:
    """Create a configured logger instance."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s │ %(levelname)-8s │ %(name)-20s │ %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()

"""
Abstract base class for all scanner modules.

Every scanner inherits from BaseScanner and implements the `scan()` method.
This provides a consistent interface for the registry and orchestrator.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from engine.models.finding import Finding


# Type alias for progress callbacks (percentage: float, message: str)
ProgressCallback = Callable[[float, str], None]


class BaseScanner(ABC):
    """Base class all scanner modules must inherit from."""

    def __init__(self, timeout: int = 10, threads: int = 50):
        self.timeout = timeout
        self.threads = threads
        self._progress_callback: Optional[ProgressCallback] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Machine-readable name (e.g., 'port_scan')."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name (e.g., 'Port Scanner')."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what this scanner does."""

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set a callback for reporting scan progress to WebSocket clients."""
        self._progress_callback = callback

    def report_progress(self, percentage: float, message: str) -> None:
        """Report progress to any registered listener."""
        if self._progress_callback:
            self._progress_callback(percentage, message)

    @abstractmethod
    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """
        Execute the scan against the target.

        Args:
            target: Domain, IP, or URL to scan.
            **kwargs: Module-specific options (e.g., jwt_token, wordlist).

        Returns:
            List of Finding objects discovered during the scan.
        """

    async def safe_scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """
        Wrapper around scan() that catches exceptions and returns
        an error finding instead of crashing the entire scan pipeline.
        """
        try:
            return await self.scan(target, **kwargs)
        except asyncio.CancelledError:
            raise  # Don't swallow cancellation
        except Exception as exc:
            return [
                Finding(
                    scanner=self.name,
                    type="Scanner Error",
                    severity="info",
                    title=f"{self.display_name} encountered an error",
                    description=f"The scanner failed with: {str(exc)}",
                    evidence=str(exc),
                )
            ]

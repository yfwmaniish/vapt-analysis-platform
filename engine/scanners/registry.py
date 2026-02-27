"""
Scanner plugin registry.

Auto-discovers and registers all scanner modules.
The orchestrator and API layer use this to find and run scanners.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from engine.scanners.base import BaseScanner


class ScannerRegistry:
    """Singleton registry of all available scanner modules."""

    _scanners: Dict[str, Type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_cls: Type[BaseScanner]) -> Type[BaseScanner]:
        """
        Decorator to register a scanner class.

        Usage:
            @ScannerRegistry.register
            class PortScanner(BaseScanner): ...
        """
        instance = scanner_cls()
        cls._scanners[instance.name] = scanner_cls
        return scanner_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseScanner]]:
        """Get a scanner class by name."""
        return cls._scanners.get(name)

    @classmethod
    def get_all(cls) -> Dict[str, Type[BaseScanner]]:
        """Get all registered scanner classes."""
        return dict(cls._scanners)

    @classmethod
    def get_names(cls) -> List[str]:
        """Get all registered scanner names."""
        return list(cls._scanners.keys())

    @classmethod
    def get_info(cls) -> List[dict]:
        """Get metadata for all registered scanners."""
        info = []
        for name, scanner_cls in cls._scanners.items():
            instance = scanner_cls()
            info.append({
                "name": instance.name,
                "display_name": instance.display_name,
                "description": instance.description,
            })
        return info

    @classmethod
    def create(cls, name: str, **kwargs) -> Optional[BaseScanner]:
        """Create an instance of a scanner by name."""
        scanner_cls = cls._scanners.get(name)
        if scanner_cls:
            return scanner_cls(**kwargs)
        return None

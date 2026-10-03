"""Public, static-first API. Importing this package does not load AI SDKs."""

from .config import ScanConfig
from .findings import Finding, ScanReport
from .ingest import scan

__version__ = "0.1.0"
__all__ = ["Finding", "ScanConfig", "ScanReport", "scan"]

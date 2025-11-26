"""
Batch Analysis Module

Automated batch processing for security controls GAP analysis.
Processes documents and URLs, executes all 8 modules, and generates HTML dashboard.
"""

from .document_parser import DocumentParser
from .url_parser import URLParser
from .orchestrator import BatchOrchestrator
from .dashboard_generator import DashboardGenerator

__all__ = [
    "DocumentParser",
    "URLParser",
    "BatchOrchestrator",
    "DashboardGenerator",
]

__version__ = "1.0.0"

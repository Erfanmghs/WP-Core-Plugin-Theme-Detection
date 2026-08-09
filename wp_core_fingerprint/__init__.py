"""WordPress core, plugin and theme version detection."""

__version__ = "3.0.1"

from wp_core_fingerprint.fingerprint import WPCoreFingerprinter, main
from wp_core_fingerprint.models import FingerprintReport
from wp_core_fingerprint.report import report_to_json, report_to_markdown

__all__ = [
    "FingerprintReport",
    "WPCoreFingerprinter",
    "main",
    "report_to_json",
    "report_to_markdown",
    "__version__",
]

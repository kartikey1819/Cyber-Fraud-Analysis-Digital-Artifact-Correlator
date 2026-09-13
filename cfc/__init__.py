"""Unified Cyber Fraud Analysis & Digital Artifact Correlator.

A dependency-free digital forensic triage pipeline for financial cyber fraud:
ingest heterogeneous investigation artifacts, normalise them, correlate the
entities across them, score the endpoints and emit a court-ready brief.
"""

__version__ = "1.0.0"

from .case import Case, run  # noqa: F401

"""Shared data models and report schema version."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REPORT_SCHEMA_VERSION = "3.0.0"
TOOL_VERSION = "3.0.0"


@dataclass
class AssetFingerprint:
    name: str
    path: str
    category: str
    weight: float
    md5: str | None = None
    size: int | None = None
    error: str | None = None


@dataclass
class TagScore:
    tag: str
    matched: list[str]
    missing: list[str]
    skipped: list[str]
    match_count: int
    total_assets: int
    weighted_score: float
    weighted_max: float
    confidence_pct: float
    unique_discriminators: list[str] = field(default_factory=list)


@dataclass
class FingerprintReport:
    target: str
    scanned_at: str
    detected_version: str | None
    detected_era: str | None
    confidence: str
    confidence_pct: float
    tags_compared: int
    supported_range: str
    top_candidates: list[dict[str, Any]]
    assets: list[dict[str, Any]]
    html_indicators: dict[str, Any]
    supplementary: list[dict[str, Any]]
    plugins_detected: list[dict[str, Any]]
    notes: list[str]
    limitations: list[str]
    asset_mismatches: list[dict[str, Any]] = field(default_factory=list)
    scan_profile: str = "normal"
    request_stats: dict[str, Any] = field(default_factory=dict)
    cache_stats: dict[str, Any] = field(default_factory=dict)
    themes_detected: list[dict[str, Any]] = field(default_factory=list)
    mu_plugins_detected: list[dict[str, Any]] = field(default_factory=list)
    crawl_enabled: bool = False
    crawl_stats: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = REPORT_SCHEMA_VERSION
    tool_version: str = TOOL_VERSION

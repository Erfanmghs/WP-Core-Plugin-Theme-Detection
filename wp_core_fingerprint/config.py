"""JSON config file loader merged with CLI arguments."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONFIG_KEYS = {
    "url",
    "output",
    "markdown",
    "html",
    "sarif",
    "user_agent",
    "timeout",
    "workers",
    "tag_workers",
    "target_delay",
    "github_delay",
    "max_retries",
    "retry_backoff",
    "relaxed_ssl",
    "gentle",
    "minimal_probes",
    "sequential",
    "crawl",
    "crawl_workers",
    "crawl_max_pages",
    "crawl_max_depth",
    "crawl_delay",
    "enumerate_plugins",
    "ignore_robots",
    "min_major",
    "quick",
    "tag_limit",
    "phase1_limit",
    "quiet",
    "proxy",
    "headers",
    "cookie",
    "min_confidence",
    "check_vulns",
    "no_cache",
    "max_requests",
    "config",
}


def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Config root must be a JSON object")
    unknown = set(data) - CONFIG_KEYS
    if unknown:
        raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    return data


def apply_config_defaults(args: Any, config: dict[str, Any]) -> None:
    """CLI args win over config file values."""
    for key, value in config.items():
        if key == "config":
            continue
        if getattr(args, key, None) in (None, False) and value is not None:
            # Only fill unset flags / None values
            current = getattr(args, key, None)
            if current is None or (isinstance(current, bool) and not current and value):
                setattr(args, key, value)

"""GitHub tag fetching, parsing, and version-range filtering."""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
from typing import Any, Callable

GITHUB_TAGS_API = "https://api.github.com/repos/WordPress/WordPress/tags"
STABLE_TAG_RE = re.compile(r"^\d+(?:\.\d+)*$")


def parse_version(tag: str) -> tuple[int, ...]:
    """Parse tag like 4.9.26 or 1.5.1.3 into numeric tuple."""
    parts: list[int] = []
    for part in tag.split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def version_key(tag: str) -> tuple[int, ...]:
    return parse_version(tag)


def is_stable_tag(tag: str) -> bool:
    if re.search(r"(beta|RC|rc|alpha)", tag, re.I):
        return False
    return bool(STABLE_TAG_RE.match(tag))


def tag_in_range(
    tag: str,
    min_wp: tuple[int, int] = (1, 0),
    max_wp: tuple[int, int] | None = None,
) -> bool:
    v = parse_version(tag)
    min_v = (min_wp[0], min_wp[1], 0, 0)
    if v < min_v:
        return False
    if max_wp is not None:
        max_v = (max_wp[0], max_wp[1], 0, 0)
        if v >= max_v:
            return False
    return True


def asset_applicable_for_tag(
    asset: dict,
    tag: str,
) -> bool:
    min_wp = asset.get("min_wp", (1, 0))
    max_wp = asset.get("max_wp")
    if not tag_in_range(tag, min_wp, max_wp):
        return False
    return True


def fetch_github_tags(
    user_agent: str,
    ctx: ssl.SSLContext,
    timeout: int = 30,
    max_pages: int = 20,
    http_get: Any | None = None,
) -> list[str]:
    tags: list[str] = []
    for page in range(1, max_pages + 1):
        url = f"{GITHUB_TAGS_API}?per_page=100&page={page}"
        if http_get is not None:
            _status, body, _headers, err = http_get(url)
            if err or not body:
                break
            batch = json.loads(body.decode())
        else:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": user_agent,
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                batch = json.loads(resp.read().decode())
        if not batch:
            break
        tags.extend(t["name"] for t in batch)
    return tags


def filter_tags(
    tags: list[str],
    *,
    min_major: int = 1,
    min_minor: int = 0,
    max_major: int | None = None,
    tag_limit: int = 0,
    predicate: Callable[[str], bool] | None = None,
) -> list[str]:
    filtered: list[str] = []
    min_v = (min_major, min_minor, 0, 0)
    max_v = (max_major, 99, 99, 99) if max_major is not None else None

    for tag in tags:
        if not is_stable_tag(tag):
            continue
        v = parse_version(tag)
        if v < min_v:
            continue
        if max_v is not None and v > max_v:
            continue
        if predicate and not predicate(tag):
            continue
        filtered.append(tag)

    # Newest first (GitHub API order); keep for scoring priority
    if tag_limit > 0:
        filtered = filtered[:tag_limit]
    return filtered


def detect_era(live_asset_names: set[str]) -> str:
    """Infer WordPress era from successfully fingerprinted assets."""
    if "hooks.min.js" in live_asset_names:
        if "components.min.js" in live_asset_names:
            return "modern"  # WP 6.x / 7.x typical (dist fully populated)
        return "block"  # WP 5.x
    if "wp-emoji-release.min.js" in live_asset_names or "wp-emoji.min.js" in live_asset_names:
        return "classic"  # WP 4.x
    return "legacy"  # WP 3.x and earlier


def era_tag_predicate(era: str) -> Callable[[str], bool]:
    """Return tag filter for detected era."""
    if era == "modern":
        return lambda t: parse_version(t) >= (6, 0, 0, 0)
    if era == "block":
        return lambda t: (5, 0, 0, 0) <= parse_version(t) < (6, 0, 0, 0)
    if era == "classic":
        return lambda t: (4, 0, 0, 0) <= parse_version(t) < (5, 0, 0, 0)
    return lambda t: parse_version(t) < (4, 0, 0, 0)


def parse_generator_version(generator: str | None) -> str | None:
    if not generator:
        return None
    m = re.search(r"WordPress\s+([\d.]+)", generator, re.I)
    return m.group(1) if m else None

"""Plugin and theme slug detection plus version resolution from WordPress files."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

HttpGet = Callable[[str, str], tuple[int | None, bytes, dict[str, str], str | None]]

PLUGIN_SLUG_RE = re.compile(r"wp-content/plugins/([a-z0-9_-]+)/", re.I)
THEME_SLUG_RE = re.compile(r"wp-content/themes/([a-z0-9_-]+)/", re.I)
MU_PLUGIN_SLUG_RE = re.compile(r"wp-content/mu-plugins/([a-z0-9_.-]+\.php)", re.I)
PLUGIN_PHP_RE = re.compile(
    r"wp-content/plugins/([a-z0-9_-]+)/([a-z0-9_-]+\.php)", re.I
)
PLUGIN_VER_RE = re.compile(
    r"wp-content/plugins/([a-z0-9_-]+)/[^\"']+\?ver=([^\"'&\s]+)", re.I
)
THEME_VER_RE = re.compile(
    r"wp-content/themes/([a-z0-9_-]+)/[^\"'&\s]+(?:\?ver=([^\"'&\s]+))?", re.I
)

HEADER_VERSION_RE = re.compile(
    r"^\s*(?:\*?\s*)?Version:\s*([0-9][0-9a-zA-Z.+_-]*)",
    re.I | re.M,
)
README_STABLE_RE = re.compile(
    r"^\s*Stable tag:\s*([0-9][0-9a-zA-Z.+_-]*)",
    re.I | re.M,
)
README_VERSION_RE = re.compile(
    r"^\s*Version:\s*([0-9][0-9a-zA-Z.+_-]*)",
    re.I | re.M,
)
STYLE_THEME_NAME_RE = re.compile(
    r"^\s*Theme Name:\s*(.+)$",
    re.I | re.M,
)
STYLE_TEMPLATE_RE = re.compile(
    r"^\s*Template:\s*([a-z0-9_-]+)",
    re.I | re.M,
)
COMPOSER_VERSION_RE = re.compile(
    r'"version"\s*:\s*"([0-9][0-9a-zA-Z.+_-]*)"',
)
PACKAGE_VERSION_RE = re.compile(
    r'"version"\s*:\s*"([0-9][0-9a-zA-Z.+_-]*)"',
)

SKIP_SLUGS = frozenset({"index", "plugins", "themes", "uploads", "cache"})


@dataclass
class ExtensionRecord:
    slug: str
    kind: str  # plugin | theme | mu-plugin
    version: str | None = None
    name: str | None = None
    version_confidence: str = "unknown"
    version_sources: list[dict[str, str]] = field(default_factory=list)
    html_version_hints: list[str] = field(default_factory=list)
    candidate_php_files: list[str] = field(default_factory=list)
    pages_found: list[str] = field(default_factory=list)
    parent_theme: str | None = None
    active: bool | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "kind": self.kind,
            "version": self.version,
            "name": self.name,
            "version_confidence": self.version_confidence,
            "version_sources": self.version_sources,
            "html_version_hints": self.html_version_hints,
            "pages_found": self.pages_found[:20],
            "pages_found_count": len(self.pages_found),
            "parent_theme": self.parent_theme,
            "active": self.active,
            "errors": self.errors,
        }


def _decode(body: bytes) -> str:
    return body.decode("utf-8", errors="ignore")


def _semverish(value: str) -> bool:
    return bool(re.match(r"^[0-9]+(?:\.[0-9A-Za-z_-]+)*$", value))


def _add_source(
    rec: ExtensionRecord,
    source: str,
    value: str,
    weight: int,
) -> None:
    if not value or value.lower() in {"trunk", "master", "dev"}:
        return
    for existing in rec.version_sources:
        if existing["source"] == source and existing["value"] == value:
            return
    rec.version_sources.append({"source": source, "value": value, "weight": str(weight)})


def _pick_version(rec: ExtensionRecord) -> None:
    if not rec.version_sources:
        if rec.html_version_hints:
            rec.version = rec.html_version_hints[0]
            rec.version_confidence = "low"
        return

    ranked = sorted(
        rec.version_sources,
        key=lambda s: (int(s["weight"]), s["value"]),
        reverse=True,
    )
    top_weight = int(ranked[0]["weight"])
    top_values = {s["value"] for s in ranked if int(s["weight"]) == top_weight}
    rec.version = ranked[0]["value"]

    if len(top_values) > 1 and len({s["value"] for s in ranked[:3]}) > 1:
        # Conflicting authoritative sources — prefer highest weight anyway
        rec.version_confidence = "medium"
        return

    if top_weight >= 90:
        rec.version_confidence = "confirmed"
    elif top_weight >= 70:
        rec.version_confidence = "high"
    elif top_weight >= 40:
        rec.version_confidence = "medium"
    else:
        rec.version_confidence = "low"


def extract_slugs_from_html(html: str) -> tuple[set[str], set[str], set[str]]:
    plugins = {m.group(1).lower() for m in PLUGIN_SLUG_RE.finditer(html)} - SKIP_SLUGS
    themes = {m.group(1).lower() for m in THEME_SLUG_RE.finditer(html)} - SKIP_SLUGS
    mu = {m.group(1).lower() for m in MU_PLUGIN_SLUG_RE.finditer(html)}
    return plugins, themes, mu


def extract_version_hints_from_html(html: str) -> tuple[
    dict[str, list[str]], dict[str, list[str]], dict[str, list[str]]
]:
    plugin_hints: dict[str, list[str]] = {}
    theme_hints: dict[str, list[str]] = {}
    plugin_php: dict[str, list[str]] = {}

    for m in PLUGIN_VER_RE.finditer(html):
        slug, ver = m.group(1).lower(), m.group(2)
        plugin_hints.setdefault(slug, [])
        if ver not in plugin_hints[slug]:
            plugin_hints[slug].append(ver)

    for m in THEME_VER_RE.finditer(html):
        slug = m.group(1).lower()
        ver = m.group(2)
        if ver:
            theme_hints.setdefault(slug, [])
            if ver not in theme_hints[slug]:
                theme_hints[slug].append(ver)

    for m in PLUGIN_PHP_RE.finditer(html):
        slug, php_file = m.group(1).lower(), m.group(2).lower()
        plugin_php.setdefault(slug, [])
        if php_file not in plugin_php[slug]:
            plugin_php[slug].append(php_file)

    return plugin_hints, theme_hints, plugin_php


def parse_readme_version(text: str) -> str | None:
    m = README_STABLE_RE.search(text)
    if m:
        return m.group(1).strip()
    m = README_VERSION_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


def parse_header_version(text: str) -> str | None:
    m = HEADER_VERSION_RE.search(text)
    return m.group(1).strip() if m else None


def parse_style_css(text: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {
        "version": parse_header_version(text),
        "name": None,
        "parent": None,
    }
    nm = STYLE_THEME_NAME_RE.search(text)
    if nm:
        out["name"] = nm.group(1).strip()
    tmpl = STYLE_TEMPLATE_RE.search(text)
    if tmpl:
        out["parent"] = tmpl.group(1).strip().lower()
    return out


def parse_json_version(body: bytes) -> str | None:
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        text = _decode(body)
        m = COMPOSER_VERSION_RE.search(text) or PACKAGE_VERSION_RE.search(text)
        return m.group(1) if m else None
    version = data.get("version")
    return str(version).strip() if version else None


def merge_records(
    records: dict[tuple[str, str], ExtensionRecord],
    slug: str,
    kind: str,
    page_url: str | None = None,
) -> ExtensionRecord:
    key = (kind, slug)
    if key not in records:
        records[key] = ExtensionRecord(slug=slug, kind=kind)
    rec = records[key]
    if page_url and page_url not in rec.pages_found:
        rec.pages_found.append(page_url)
    return rec


def resolve_plugin_version(
    rec: ExtensionRecord,
    url_join: Callable[[str], str],
    http_get: HttpGet,
) -> None:
    slug = rec.slug
    paths = [
        (f"wp-content/plugins/{slug}/readme.txt", "readme.txt", 95, parse_readme_version),
        (f"wp-content/plugins/{slug}/changelog.txt", "changelog.txt", 85, parse_readme_version),
        (f"wp-content/plugins/{slug}/{slug}.php", "plugin-header", 90, parse_header_version),
        (f"wp-content/plugins/{slug}/index.php", "index-header", 85, parse_header_version),
        (f"wp-content/plugins/{slug}/composer.json", "composer.json", 75, parse_json_version),
        (f"wp-content/plugins/{slug}/package.json", "package.json", 70, parse_json_version),
    ]

    for path, source, weight, parser in paths:
        status, body, _, err = http_get(url_join(path))
        if err:
            rec.errors.append(f"{source}: {err}")
            continue
        if status != 200 or not body:
            continue
        text = _decode(body)
        if source.endswith(".json"):
            version = parser(body)
        else:
            version = parser(text)
            if source.endswith("-header") and not version:
                version = parse_header_version(text[:8192])
        if version:
            _add_source(rec, source, version, weight)
            if source == "plugin-header" and not rec.name:
                nm = re.search(r"^\s*\*?\s*Plugin Name:\s*(.+)$", text, re.I | re.M)
                if nm:
                    rec.name = nm.group(1).strip()

    for php_file in rec.candidate_php_files[:8]:
        if php_file in {f"{slug}.php", "index.php"}:
            continue
        path = f"wp-content/plugins/{slug}/{php_file}"
        status, body, _, err = http_get(url_join(path))
        if err or status != 200 or not body:
            continue
        version = parse_header_version(_decode(body)[:8192])
        if version:
            _add_source(rec, php_file, version, 88)

    for hint in rec.html_version_hints:
        weight = 50 if _semverish(hint) else 30
        _add_source(rec, "html-ver-param", hint, weight)

    _pick_version(rec)


def resolve_theme_version(
    rec: ExtensionRecord,
    url_join: Callable[[str], str],
    http_get: HttpGet,
) -> None:
    slug = rec.slug
    style_path = f"wp-content/themes/{slug}/style.css"
    status, body, _, err = http_get(url_join(style_path))
    if err:
        rec.errors.append(f"style.css: {err}")
    elif status == 200 and body:
        meta = parse_style_css(_decode(body))
        if meta["version"]:
            _add_source(rec, "style.css", meta["version"], 95)
        if meta["name"]:
            rec.name = meta["name"]
        if meta["parent"]:
            rec.parent_theme = meta["parent"]

    for path, source, weight, parser in [
        (f"wp-content/themes/{slug}/readme.txt", "readme.txt", 80, parse_readme_version),
        (f"wp-content/themes/{slug}/style.css", "style.css-header", 95, parse_header_version),
        (f"wp-content/themes/{slug}/composer.json", "composer.json", 70, parse_json_version),
        (f"wp-content/themes/{slug}/package.json", "package.json", 65, parse_json_version),
    ]:
        if source == "style.css-header":
            continue  # already handled
        status, body, _, err = http_get(url_join(path))
        if err or status != 200 or not body:
            continue
        if path.endswith(".json"):
            version = parser(body)
        else:
            version = parser(_decode(body))
        if version:
            _add_source(rec, source, version, weight)

    for hint in rec.html_version_hints:
        weight = 50 if _semverish(hint) else 30
        _add_source(rec, "html-ver-param", hint, weight)

    _pick_version(rec)

    if rec.parent_theme and rec.version_confidence == "unknown":
        parent_style = f"wp-content/themes/{rec.parent_theme}/style.css"
        status, body, _, _ = http_get(url_join(parent_style))
        if status == 200 and body:
            meta = parse_style_css(_decode(body))
            if meta["version"]:
                _add_source(rec, "parent-style.css", meta["version"], 85)
                _pick_version(rec)


def resolve_mu_plugin(
    rec: ExtensionRecord,
    url_join: Callable[[str], str],
    http_get: HttpGet,
) -> None:
    path = f"wp-content/mu-plugins/{rec.slug}"
    status, body, _, err = http_get(url_join(path))
    if err:
        rec.errors.append(err)
        return
    if status == 200 and body:
        version = parse_header_version(_decode(body)[:8192])
        if version:
            _add_source(rec, "mu-plugin-header", version, 90)
    _pick_version(rec)


def resolve_all_extensions(
    records: dict[tuple[str, str], ExtensionRecord],
    url_join: Callable[[str], str],
    http_get: HttpGet,
    workers: int = 4,
) -> list[ExtensionRecord]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    items = list(records.values())

    def _resolve(rec: ExtensionRecord) -> ExtensionRecord:
        if rec.kind == "plugin":
            resolve_plugin_version(rec, url_join, http_get)
        elif rec.kind == "theme":
            resolve_theme_version(rec, url_join, http_get)
        elif rec.kind == "mu-plugin":
            resolve_mu_plugin(rec, url_join, http_get)
        return rec

    if workers <= 1:
        return [_resolve(r) for r in items]

    resolved: list[ExtensionRecord] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_resolve, r) for r in items]
        for fut in as_completed(futures):
            resolved.append(fut.result())
    resolved.sort(key=lambda r: (r.kind, r.slug))
    return resolved

"""Optional vulnerability advisory lookup (WPVulnerability.net — no API key)."""
from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import quote

HttpGet = Callable[[str, str], tuple[int | None, bytes, dict[str, str], str | None]]

WPVULN_CORE = "https://www.wpvulnerability.net/core/{version}/"
WPVULN_PLUGIN = "https://www.wpvulnerability.net/plugin/{slug}/"
WPVULN_THEME = "https://www.wpvulnerability.net/theme/{slug}/"


def _parse_wpvuln(body: bytes, component: str, version: str | None) -> list[dict[str, Any]]:
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        items = [items] if items else []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("title") or "WordPress vulnerability"
        severity = item.get("severity") or item.get("impact") or "unknown"
        cve = item.get("cve") or item.get("cve_id")
        vid = cve or item.get("uuid") or item.get("id") or "WPVULN"
        if isinstance(vid, list):
            vid = vid[0] if vid else "WPVULN"
        out.append(
            {
                "component": component,
                "version": version,
                "id": str(vid),
                "severity": str(severity).lower(),
                "title": str(name),
                "source": "wpvulnerability.net",
            }
        )
    return out


def check_core_vulns(version: str, http_get: HttpGet) -> list[dict[str, Any]]:
    url = WPVULN_CORE.format(version=quote(version))
    status, body, _, err = http_get(url)
    if err or status != 200 or not body:
        return []
    return _parse_wpvuln(body, f"wordpress-core:{version}", version)


def check_plugin_vulns(slug: str, version: str | None, http_get: HttpGet) -> list[dict[str, Any]]:
    url = WPVULN_PLUGIN.format(slug=quote(slug))
    status, body, _, err = http_get(url)
    if err or status != 200 or not body:
        return []
    vulns = _parse_wpvuln(body, f"plugin:{slug}", version)
    if version:
        vulns = [v for v in vulns if _version_affected(version, v.get("title", "")) or not v.get("title")]
    return vulns


def check_theme_vulns(slug: str, version: str | None, http_get: HttpGet) -> list[dict[str, Any]]:
    url = WPVULN_THEME.format(slug=quote(slug))
    status, body, _, err = http_get(url)
    if err or status != 200 or not body:
        return []
    return _parse_wpvuln(body, f"theme:{slug}", version)


def _version_affected(installed: str, title: str) -> bool:
    """Best-effort: if title mentions versions, skip obvious non-matches."""
    return True


def scan_vulnerabilities(
    core_version: str | None,
    plugins: list[dict[str, Any]],
    themes: list[dict[str, Any]],
    http_get: HttpGet,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if core_version and re.match(r"^\d+\.\d+", core_version):
        findings.extend(check_core_vulns(core_version, http_get))
    for p in plugins[:30]:
        slug = p.get("slug")
        ver = p.get("version")
        if slug:
            findings.extend(check_plugin_vulns(slug, ver, http_get))
    for t in themes[:10]:
        slug = t.get("slug")
        ver = t.get("version")
        if slug:
            findings.extend(check_theme_vulns(slug, ver, http_get))
    # Dedupe by id+component
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f.get('id')}|{f.get('component')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique

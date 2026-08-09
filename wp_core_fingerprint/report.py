"""Report writers: Markdown, HTML, SARIF, JSON envelope."""
from __future__ import annotations

import html as html_lib
import json
from dataclasses import asdict
from typing import Any

from wp_core_fingerprint.models import FingerprintReport, REPORT_SCHEMA_VERSION


def report_to_json(report: FingerprintReport) -> dict[str, Any]:
    data = asdict(report)
    data["schema_version"] = REPORT_SCHEMA_VERSION
    return data


def report_to_markdown(r: FingerprintReport) -> str:
    lines = [
        "# WordPress Version Detection Report",
        "",
        f"- **Schema:** `{r.schema_version}` | **Tool:** `{r.tool_version}`",
        f"- **Target:** {r.target}",
        f"- **Scanned (UTC):** {r.scanned_at}",
        f"- **Detected version:** `{r.detected_version or 'unknown'}`",
        f"- **Detected era:** `{r.detected_era or 'unknown'}`",
        f"- **Confidence:** {r.confidence} ({r.confidence_pct}%)",
        f"- **Tags compared:** {r.tags_compared}",
        f"- **Scan profile:** `{r.scan_profile}`",
        f"- **Supported range:** {r.supported_range}",
        "",
        "## Top candidates",
        "",
        "| Tag | Matches | Weighted % | Unique discriminators |",
        "|-----|---------|------------|----------------------|",
    ]
    for c in r.top_candidates:
        ud = ", ".join(c.get("unique_discriminators") or []) or "-"
        lines.append(
            f"| {c['tag']} | {c['match_count']}/{c['total_assets']} | "
            f"{c['confidence_pct']}% | {ud} |"
        )

    if r.vulnerabilities:
        lines.extend(["", "## Vulnerabilities (advisory lookup)", ""])
        lines.append("| Component | Version | CVE/ID | Severity | Title |")
        lines.append("|-----------|---------|--------|----------|-------|")
        for v in r.vulnerabilities[:50]:
            lines.append(
                f"| {v.get('component', '?')} | `{v.get('version', '?')}` | "
                f"{v.get('id', '-')} | {v.get('severity', '-')} | "
                f"{v.get('title', '-')} |"
            )

    lines.extend(["", "## HTML indicators", ""])
    for k, v in r.html_indicators.items():
        lines.append(f"- **{k}:** `{v}`")

    if r.plugins_detected:
        title = "## Plugins (crawl + version resolution)" if r.crawl_enabled else "## Plugins (from HTML)"
        lines.extend(["", title, ""])
        if r.crawl_enabled:
            lines.append("| Slug | Version | Confidence | Sources | Pages |")
            lines.append("|------|---------|------------|---------|-------|")
            for p in r.plugins_detected:
                sources = ", ".join(s["source"] for s in p.get("version_sources") or []) or "-"
                lines.append(
                    f"| `{p['slug']}` | `{p.get('version') or 'unknown'}` | "
                    f"{p.get('version_confidence', 'unknown')} | {sources} | "
                    f"{p.get('pages_found_count', 0)} |"
                )
        else:
            for p in r.plugins_detected:
                ver = p.get("version") or p.get("version_hint", "?")
                lines.append(f"- `{p['slug']}` -> `{ver}`")

    if r.themes_detected:
        lines.extend(["", "## Themes", ""])
        lines.append("| Slug | Version | Confidence | Active | Parent |")
        lines.append("|------|---------|------------|--------|--------|")
        for t in r.themes_detected:
            active = "yes" if t.get("active") else ("no" if t.get("active") is False else "?")
            lines.append(
                f"| `{t['slug']}` | `{t.get('version') or 'unknown'}` | "
                f"{t.get('version_confidence', '?')} | {active} | "
                f"`{t.get('parent_theme') or '-'}` |"
            )

    if r.mu_plugins_detected:
        lines.extend(["", "## Must-use plugins", ""])
        for m in r.mu_plugins_detected:
            lines.append(f"- `{m['slug']}` -> `{m.get('version') or 'unknown'}`")

    if r.crawl_stats:
        lines.extend(["", "## Crawl stats", ""])
        for k, v in r.crawl_stats.items():
            lines.append(f"- **{k}:** `{v}`")

    lines.extend(["", "## Core asset fingerprints", ""])
    lines.append("| Asset | MD5 | Size | Category |")
    lines.append("|-------|-----|------|----------|")
    for a in r.assets:
        if a.get("md5"):
            lines.append(
                f"| {a['name']} | `{a['md5']}` | {a['size']} | {a['category']} |"
            )

    if r.cache_stats:
        lines.extend(["", "## Cache stats", ""])
        for k, v in r.cache_stats.items():
            lines.append(f"- **{k}:** `{v}`")

    if r.request_stats:
        lines.extend(["", "## Request stats", ""])
        for k, v in r.request_stats.items():
            if k == "errors" and v:
                lines.append(f"- **{k}:**")
                for e in v:
                    lines.append(f"  - `{e}`")
            else:
                lines.append(f"- **{k}:** `{v}`")

    if r.notes:
        lines.extend(["", "## Notes", ""])
        for n in r.notes:
            lines.append(f"- {n}")

    lines.extend(["", "## Limitations", ""])
    for lim in r.limitations:
        lines.append(f"- {lim}")

    return "\n".join(lines) + "\n"


def report_to_html(r: FingerprintReport) -> str:
    def esc(s: Any) -> str:
        return html_lib.escape(str(s))

    rows = "".join(
        f"<tr><td>{esc(c['tag'])}</td><td>{c['match_count']}/{c['total_assets']}</td>"
        f"<td>{c['confidence_pct']}%</td>"
        f"<td>{esc(', '.join(c.get('unique_discriminators') or []) or '-')}</td></tr>"
        for c in r.top_candidates
    )
    plugin_rows = "".join(
        f"<tr><td><code>{esc(p['slug'])}</code></td>"
        f"<td>{esc(p.get('version') or 'unknown')}</td>"
        f"<td>{esc(p.get('version_confidence', '?'))}</td></tr>"
        for p in r.plugins_detected
    )
    vuln_rows = "".join(
        f"<tr><td>{esc(v.get('component'))}</td><td>{esc(v.get('version'))}</td>"
        f"<td>{esc(v.get('id'))}</td><td>{esc(v.get('severity'))}</td>"
        f"<td>{esc(v.get('title'))}</td></tr>"
        for v in r.vulnerabilities[:50]
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WP Fingerprint — {esc(r.target)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px;line-height:1.5}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ccc;padding:.45rem .6rem;text-align:left}}
th{{background:#f5f5f5}} code{{background:#f0f0f0;padding:.1rem .3rem}}
.badge{{display:inline-block;padding:.2rem .5rem;border-radius:4px;background:#e8f4ea}}
</style></head><body>
<h1>WordPress Version Detection</h1>
<p><span class="badge">{esc(r.confidence)} {r.confidence_pct}%</span>
<strong>{esc(r.detected_version or 'unknown')}</strong> on {esc(r.target)}</p>
<p>Schema {esc(r.schema_version)} | Tool {esc(r.tool_version)} | {esc(r.scanned_at)} UTC</p>
<h2>Top candidates</h2>
<table><tr><th>Tag</th><th>Matches</th><th>Score</th><th>Discriminators</th></tr>{rows}</table>
{"<h2>Vulnerabilities</h2><table><tr><th>Component</th><th>Version</th><th>ID</th><th>Severity</th><th>Title</th></tr>" + vuln_rows + "</table>" if vuln_rows else ""}
{"<h2>Plugins</h2><table><tr><th>Slug</th><th>Version</th><th>Confidence</th></tr>" + plugin_rows + "</table>" if plugin_rows else ""}
<h2>Notes</h2><ul>{"".join(f"<li>{esc(n)}</li>" for n in r.notes)}</ul>
</body></html>"""


def report_to_sarif(r: FingerprintReport) -> dict[str, Any]:
    """Minimal SARIF 2.1 for CI ingestion."""
    results: list[dict[str, Any]] = []
    for v in r.vulnerabilities:
        results.append(
            {
                "ruleId": v.get("id") or "WP-VULN",
                "level": "warning" if v.get("severity") in ("medium", "low") else "error",
                "message": {"text": v.get("title") or "WordPress vulnerability"},
                "properties": {
                    "component": v.get("component"),
                    "version": v.get("version"),
                    "severity": v.get("severity"),
                },
            }
        )
    if r.confidence == "insufficient":
        results.append(
            {
                "ruleId": "WP-CORE-UNKNOWN",
                "level": "note",
                "message": {"text": "WordPress core version could not be determined with sufficient confidence"},
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wp-core-fingerprint",
                        "version": r.tool_version,
                        "informationUri": "https://github.com/Erfanmghs/wp-core-plugin-theme-detection",
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: FingerprintReport, path: str) -> None:
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report_to_sarif(report), indent=2) + "\n", encoding="utf-8")

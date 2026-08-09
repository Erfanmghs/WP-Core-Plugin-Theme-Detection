#!/usr/bin/env python3
"""
WordPress core, plugin and theme detection for remote sites.

Core patch fingerprint by default; use --crawl for plugin/theme inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wp_core_fingerprint.advisories import scan_vulnerabilities
from wp_core_fingerprint.assets import (
    ANCHOR_ASSET_NAMES,
    ASSET_CATALOG,
    SUPPORTED_VERSION_RANGE,
)
from wp_core_fingerprint.cache import AssetCache
from wp_core_fingerprint.config import apply_config_defaults, load_config
from wp_core_fingerprint.crawler import WordPressExtensionCrawler
from wp_core_fingerprint.http_client import RateLimitedHttp
from wp_core_fingerprint.models import (
    AssetFingerprint,
    FingerprintReport,
    TagScore,
    TOOL_VERSION,
)
from wp_core_fingerprint.report import (
    report_to_html,
    report_to_json,
    report_to_markdown,
    write_sarif,
)
from wp_core_fingerprint.tags import (
    asset_applicable_for_tag,
    detect_era,
    era_tag_predicate,
    fetch_github_tags,
    filter_tags,
    parse_generator_version,
    parse_version,
)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
GITHUB_RAW = "https://raw.githubusercontent.com/WordPress/WordPress/{tag}/{path}"

SUPPLEMENTARY_PATHS = [
    ("version.php", "wp-includes/version.php", "core-file"),
    ("readme.html", "readme.html", "disclosure"),
    ("license.txt", "license.txt", "disclosure"),
    ("wp-json", "wp-json/", "rest-root"),
    ("feed", "feed/", "feed"),
    ("debug.log", "wp-content/debug.log", "sensitive"),
]

CATALOG_BY_NAME = {a["name"]: a for a in ASSET_CATALOG}

CONFIDENCE_RANK = {"insufficient": 0, "low": 1, "medium": 2, "high": 3}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_LOW_CONFIDENCE = 2
EXIT_UNREACHABLE = 3


GENTLE_DEFAULTS = {
    "target_delay": 1.25,
    "github_delay": 0.08,
    "workers": 1,
    "tag_workers": 6,
    "max_retries": 4,
    "retry_backoff": 2.0,
    "relaxed_ssl": True,
    "minimal_probes": True,
    "sequential_target": True,
}


class WPCoreFingerprinter:
    def __init__(
        self,
        base_url: str,
        user_agent: str = DEFAULT_UA,
        timeout: int = 30,
        workers: int = 3,
        tag_workers: int = 8,
        min_major: int = 1,
        quick: bool = False,
        tag_limit: int = 0,
        phase1_limit: int = 60,
        target_delay: float = 0.75,
        github_delay: float = 0.05,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
        relaxed_ssl: bool = False,
        gentle: bool = False,
        minimal_probes: bool = False,
        sequential_target: bool = False,
        crawl: bool = False,
        crawl_workers: int = 2,
        crawl_max_pages: int = 50,
        crawl_max_depth: int = 3,
        crawl_delay: float | None = None,
        enumerate_plugins: bool = False,
        ignore_robots: bool = False,
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
        cookie: str | None = None,
        use_cache: bool = True,
        check_vulns: bool = False,
        max_requests: int = 0,
    ) -> None:
        if gentle:
            target_delay = GENTLE_DEFAULTS["target_delay"]
            github_delay = GENTLE_DEFAULTS["github_delay"]
            workers = GENTLE_DEFAULTS["workers"]
            tag_workers = GENTLE_DEFAULTS["tag_workers"]
            max_retries = GENTLE_DEFAULTS["max_retries"]
            retry_backoff = GENTLE_DEFAULTS["retry_backoff"]
            relaxed_ssl = GENTLE_DEFAULTS["relaxed_ssl"]
            minimal_probes = GENTLE_DEFAULTS["minimal_probes"]
            sequential_target = GENTLE_DEFAULTS["sequential_target"]

        self.base_url = base_url.rstrip("/") + "/"
        self.user_agent = user_agent
        self.timeout = timeout
        self.workers = workers
        self.tag_workers = tag_workers
        self.min_major = min_major
        self.quick = quick
        self.tag_limit = tag_limit
        self.phase1_limit = phase1_limit
        self.sequential_target = sequential_target
        self.minimal_probes = minimal_probes
        self.gentle = gentle
        self.crawl = crawl
        self.crawl_workers = crawl_workers
        self.crawl_max_pages = crawl_max_pages
        self.crawl_max_depth = crawl_max_depth
        self.crawl_delay = crawl_delay
        self.enumerate_plugins = enumerate_plugins
        self.ignore_robots = ignore_robots
        self.check_vulns = check_vulns
        self.scan_profile = "gentle" if gentle else "normal"
        self.http = RateLimitedHttp(
            user_agent=user_agent,
            timeout=timeout,
            target_delay=target_delay,
            github_delay=github_delay,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
            relaxed_ssl=relaxed_ssl,
            proxy=proxy,
            extra_headers=extra_headers,
            cookie=cookie,
            max_requests=max_requests,
        )
        self.ctx = self.http.ctx
        self.asset_cache = AssetCache(enabled=use_cache)
        self._github_cache: dict[str, bytes | None] = {}

    def _request(
        self, url: str, method: str = "GET"
    ) -> tuple[int | None, bytes, dict[str, str], str | None]:
        return self.http.get(url, method)

    def url(self, path: str) -> str:
        return urllib.parse.urljoin(self.base_url, path.lstrip("/"))

    def md5(self, data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    def fetch_asset(self, spec: dict[str, Any]) -> AssetFingerprint:
        path = spec["live_path"]
        url = self.url(path)
        status, body, _, err = self._request(url)
        fp = AssetFingerprint(
            name=spec["name"],
            path=path,
            category=spec["category"],
            weight=float(spec["weight"]),
        )
        if err:
            fp.error = err
            return fp
        if status != 200 or not body:
            fp.error = f"HTTP {status}, {len(body)} bytes"
            return fp
        fp.md5 = self.md5(body)
        fp.size = len(body)
        return fp

    def collect_assets(self) -> list[AssetFingerprint]:
        assets: list[AssetFingerprint] = []
        if self.sequential_target or self.workers <= 1:
            for spec in ASSET_CATALOG:
                assets.append(self.fetch_asset(spec))
        else:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = [pool.submit(self.fetch_asset, spec) for spec in ASSET_CATALOG]
                for fut in as_completed(futures):
                    assets.append(fut.result())
        assets.sort(key=lambda a: a.name)
        return assets

    def analyze_html(self, html: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "generator_meta": None,
            "generator_version": None,
            "core_ver_hashes": [],
            "emoji_pack": None,
            "jquery_version": None,
            "jquery_migrate_version": None,
            "wp_hooks_ver": None,
            "wp_i18n_ver": None,
            "concatemoji_ver": None,
            "is_wordpress": False,
        }

        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            html,
            re.I,
        )
        if gen:
            out["generator_meta"] = gen.group(1)
            out["generator_version"] = parse_generator_version(gen.group(1))
            out["is_wordpress"] = "wordpress" in gen.group(1).lower()

        if "wp-includes/" in html or "wp-content/" in html:
            out["is_wordpress"] = True

        out["core_ver_hashes"] = sorted(
            set(re.findall(r"wp-includes/[^\"']+\?ver=([a-f0-9]{32})", html))
        )

        em = re.search(r"emoji/([0-9.]+)/", html)
        if em:
            out["emoji_pack"] = em.group(1)

        jq = re.search(r"jquery(?:\.min)?\.js\?ver=([0-9.]+)", html)
        if jq:
            out["jquery_version"] = jq.group(1)

        jqm = re.search(r"jquery-migrate(?:\.min)?\.js\?ver=([0-9.]+)", html)
        if jqm:
            out["jquery_migrate_version"] = jqm.group(1)

        hooks = re.search(r"hooks\.min\.js\?ver=([a-f0-9]+)", html)
        if hooks:
            out["wp_hooks_ver"] = hooks.group(1)

        i18n = re.search(r"i18n\.min\.js\?ver=([a-f0-9]+)", html)
        if i18n:
            out["wp_i18n_ver"] = i18n.group(1)

        concat = re.search(r"concatemoji[^\"']+\?ver=([a-f0-9]{32})", html)
        if concat:
            out["concatemoji_ver"] = concat.group(1)

        return out

    def extract_plugins(self, html: str) -> list[dict[str, str]]:
        plugins: dict[str, str] = {}
        for m in re.finditer(
            r"wp-content/plugins/([a-z0-9_-]+)/[^\"']+\?ver=([^\"'&\s]+)",
            html,
            re.I,
        ):
            slug, ver = m.group(1), m.group(2)
            if slug not in plugins:
                plugins[slug] = ver
        return [{"slug": s, "version_hint": v} for s, v in sorted(plugins.items())]

    def supplementary_probes(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        skip_in_minimal = {"debug.log", "wp-json", "feed", "license.txt"}
        for label, path, category in SUPPLEMENTARY_PATHS:
            if self.minimal_probes and label in skip_in_minimal:
                continue
            url = self.url(path)
            status, body, _, err = self._request(url)
            entry: dict[str, Any] = {
                "id": label,
                "path": path,
                "url": url,
                "category": category,
                "status": status,
                "size": len(body),
                "error": err,
            }
            if label == "version.php" and status == 200 and len(body) == 0:
                entry["note"] = "PHP executes; no plaintext version leak (expected)"
            if label == "readme.html" and body:
                text = body.decode("utf-8", errors="ignore")
                rm = re.search(r"Version\s+([0-9.]+)", text, re.I)
                if rm:
                    entry["readme_version"] = rm.group(1)
            if label == "debug.log" and status == 200 and len(body) > 0:
                entry["note"] = "Public debug.log detected (information disclosure risk)"
                text = body.decode("utf-8", errors="ignore")
                m = re.search(r"added in version (\d+\.\d+\.\d+)", text)
                if m:
                    entry["debug_min_version_hint"] = m.group(1)
            if label == "wp-json" and body:
                try:
                    data = json.loads(body.decode("utf-8"))
                    entry["namespaces_count"] = len(data.get("namespaces", []))
                except json.JSONDecodeError:
                    pass
            results.append(entry)
        return results

    def fetch_github_asset(self, tag: str, paths: list[str]) -> bytes | None:
        for path in paths:
            key = f"{tag}|{path}"
            if key in self._github_cache:
                cached = self._github_cache[key]
                if cached is not None:
                    return cached
                continue
            cached = self.asset_cache.get_asset(tag, path)
            if cached:
                self._github_cache[key] = cached
                return cached
            url = GITHUB_RAW.format(tag=tag, path=path)
            status, data, _, _err = self.http.get(url)
            if status == 200 and data:
                self.asset_cache.put_asset(tag, path, data)
                self._github_cache[key] = data
                return data
            self._github_cache[key] = None
        return None

    def _load_github_tags(self) -> list[str]:
        cached = self.asset_cache.get_tag_list()
        if cached:
            return cached
        tags = fetch_github_tags(
            self.user_agent,
            self.ctx,
            self.timeout,
            http_get=self.http.get,
        )
        self.asset_cache.put_tag_list(tags)
        return tags

    def applicable_assets(self, tag: str, live: dict[str, AssetFingerprint]) -> list[str]:
        names: list[str] = []
        for spec in ASSET_CATALOG:
            if not asset_applicable_for_tag(spec, tag):
                continue
            fp = live.get(spec["name"])
            if fp and fp.md5:
                names.append(spec["name"])
        return names

    def score_tag(
        self,
        tag: str,
        live: dict[str, AssetFingerprint],
        asset_names: list[str] | None = None,
    ) -> TagScore | None:
        matched: list[str] = []
        missing: list[str] = []
        skipped: list[str] = []
        weighted = 0.0
        max_weight = 0.0

        names = asset_names or self.applicable_assets(tag, live)
        if not names:
            return None

        for name in names:
            spec = CATALOG_BY_NAME[name]
            w = float(spec["weight"])
            max_weight += w
            fp = live[name]
            gh_data = self.fetch_github_asset(tag, spec["github_paths"])
            if gh_data is None:
                skipped.append(name)
                continue
            if self.md5(gh_data) == fp.md5:
                matched.append(name)
                weighted += w
            else:
                missing.append(name)

        if not matched:
            return None

        pct = round(100.0 * weighted / max_weight, 1) if max_weight else 0.0
        return TagScore(
            tag=tag,
            matched=matched,
            missing=missing,
            skipped=skipped,
            match_count=len(matched),
            total_assets=len(names),
            weighted_score=weighted,
            weighted_max=max_weight,
            confidence_pct=pct,
        )

    def phase1_asset_names(self, live: dict[str, AssetFingerprint]) -> list[str]:
        names: list[str] = []
        for n in ANCHOR_ASSET_NAMES:
            fp = live.get(n)
            if fp and fp.md5:
                names.append(n)
        if not names:
            names = [n for n, fp in live.items() if fp.md5][:4]
        return names

    def score_tags_parallel(
        self,
        tags: list[str],
        live: dict[str, AssetFingerprint],
        asset_names: list[str] | None = None,
    ) -> list[TagScore]:
        scored: list[TagScore] = []
        with ThreadPoolExecutor(max_workers=self.tag_workers) as pool:
            futures = {
                pool.submit(self.score_tag, tag, live, asset_names): tag for tag in tags
            }
            for fut in as_completed(futures):
                ts = fut.result()
                if ts:
                    scored.append(ts)
        return scored

    def find_unique_discriminators(
        self, candidates: list[TagScore], live: dict[str, AssetFingerprint]
    ) -> None:
        if len(candidates) < 2:
            return
        top3 = candidates[:3]
        all_names = set()
        for c in top3:
            all_names.update(c.matched)
        for asset_name in all_names:
            fp = live.get(asset_name)
            if not fp or not fp.md5:
                continue
            tags_with_match = [c.tag for c in top3 if asset_name in c.matched]
            if len(tags_with_match) == 1 and tags_with_match[0] == top3[0].tag:
                top3[0].unique_discriminators.append(asset_name)

    def infer_version_floor(self, html_ind: dict[str, Any], supp: list[dict]) -> list[str]:
        notes: list[str] = []
        gv = html_ind.get("generator_version")
        if gv:
            notes.append(f"Generator meta reports WordPress {gv}")
        for s in supp:
            if s.get("readme_version"):
                notes.append(f"readme.html reports Version {s['readme_version']}")
        jq = html_ind.get("jquery_version")
        if jq:
            notes.append(f"jQuery {jq} observed in HTML")
        emoji = html_ind.get("emoji_pack") or ""
        if emoji:
            notes.append(f"Twemoji pack {emoji} observed")
        for s in supp:
            if s.get("debug_min_version_hint"):
                notes.append(
                    f"debug.log references WP {s['debug_min_version_hint']}+ API messages"
                )
        return notes

    def mismatch_analysis(
        self, best_tag: str, live: dict[str, AssetFingerprint]
    ) -> list[dict[str, Any]]:
        analysis: list[dict[str, Any]] = []
        for name in self.applicable_assets(best_tag, live):
            spec = CATALOG_BY_NAME[name]
            fp = live[name]
            gh = self.fetch_github_asset(best_tag, spec["github_paths"])
            if gh is None:
                continue
            gh_md5 = self.md5(gh)
            if gh_md5 == fp.md5:
                continue
            analysis.append(
                {
                    "asset": name,
                    "live_md5": fp.md5,
                    "reference_md5": gh_md5,
                    "live_size": fp.size,
                    "reference_size": len(gh),
                    "size_delta": (fp.size or 0) - len(gh),
                    "note": (
                        "Same size, content differs"
                        if fp.size == len(gh)
                        else "Size differs; possible customization"
                    ),
                }
            )
        return analysis

    def confidence_label(self, pct: float, unique_count: int, match_count: int) -> str:
        if unique_count >= 1 and match_count >= 4:
            return "high"
        if pct >= 75:
            return "high"
        if pct >= 55 or match_count >= 4:
            return "medium"
        if match_count >= 2:
            return "low"
        return "insufficient"

    def resolve_candidate_tags(
        self,
        all_tags: list[str],
        era: str,
        html_ind: dict[str, Any],
        supplementary: list[dict[str, Any]],
    ) -> list[str]:
        if self.quick:
            return filter_tags(
                all_tags,
                min_major=6,
                tag_limit=self.tag_limit or 24,
                predicate=lambda t: parse_version(t) >= (6, 9, 0, 0),
            )

        predicate = era_tag_predicate(era)
        candidates = filter_tags(
            all_tags,
            min_major=self.min_major,
            tag_limit=0,
            predicate=predicate,
        )

        # Narrow using disclosed versions when available
        disclosed: str | None = html_ind.get("generator_version")
        for s in supplementary:
            if s.get("readme_version"):
                disclosed = s["readme_version"]

        if disclosed:
            dv = parse_version(disclosed)
            major = dv[0]
            minor = dv[1] if len(dv) > 1 else 0
            narrowed = [
                t
                for t in candidates
                if parse_version(t)[:2] == (major, minor)
            ]
            if narrowed:
                candidates = narrowed
                return candidates

        if self.tag_limit > 0:
            candidates = candidates[: self.tag_limit]
        return candidates

    def run_extension_crawl(self, seed_html: str) -> tuple[list[dict], list[dict], list[dict], dict, list[str]]:
        """Crawl site pages and resolve plugin/theme versions from source files."""
        crawler = WordPressExtensionCrawler(
            base_url=self.base_url,
            http_get=self.http.get,
            max_pages=self.crawl_max_pages,
            max_depth=self.crawl_max_depth,
            workers=self.crawl_workers,
            crawl_delay=self.crawl_delay,
            enumerate_plugins=self.enumerate_plugins,
            ignore_robots=self.ignore_robots,
        )
        result = crawler.run(initial_html=seed_html)
        return (
            result.plugins,
            result.themes,
            result.mu_plugins,
            result.stats.to_dict(),
            result.notes,
        )

    def run(self) -> FingerprintReport:
        notes: list[str] = []
        limitations = [
            f"Compares against GitHub stable release tags ({SUPPORTED_VERSION_RANGE})",
            "version.php does not return plaintext over HTTP (PHP execution)",
            "Generator meta tag often removed in production",
            "Minor CDN/build differences can prevent 100% asset match",
            "Patch level inferred statistically; not a substitute for patch management review",
            "Very old installs (pre-3.8) have fewer fingerprint assets available",
        ]

        status, homepage_body, _, err = self._request(self.base_url)
        if err:
            raise RuntimeError(f"Cannot reach target: {err}")
        html = homepage_body.decode("utf-8", errors="ignore")
        html_ind = self.analyze_html(html)
        plugins = self.extract_plugins(html)

        assets = self.collect_assets()
        live_map = {a.name: a for a in assets}
        live_ok = {n for n, fp in live_map.items() if fp.md5}

        if not html_ind["is_wordpress"] and len(live_ok) < 2:
            notes.append("Target may not be WordPress or blocks asset access")

        era = detect_era(live_ok)
        notes.append(f"Detected era: {era} (from {len(live_ok)} fingerprint assets)")
        notes.append(f"Scan profile: {self.scan_profile}")

        supplementary = self.supplementary_probes()
        notes.extend(self.infer_version_floor(html_ind, supplementary))

        all_tags = self._load_github_tags()
        candidate_tags = self.resolve_candidate_tags(all_tags, era, html_ind, supplementary)
        notes.append(f"Comparing against {len(candidate_tags)} GitHub release tags")
        if self.asset_cache.stats.get("hits", 0):
            notes.append(f"Reference cache hits: {self.asset_cache.stats['hits']}")

        # Phase 1: fast anchor scoring
        anchor_names = self.phase1_asset_names(live_map)
        phase1 = self.score_tags_parallel(candidate_tags, live_map, anchor_names)
        phase1.sort(
            key=lambda x: (x.weighted_score, x.match_count, x.confidence_pct),
            reverse=True,
        )

        if phase1:
            finalists = [s.tag for s in phase1[: self.phase1_limit]]
        else:
            finalists = candidate_tags[: self.phase1_limit]

        if finalists and self.asset_cache.enabled:
            prefetch_paths: set[str] = set()
            for spec in ASSET_CATALOG:
                for gp in spec["github_paths"]:
                    prefetch_paths.add(gp)
            for tag in finalists[:8]:
                self.asset_cache.prefetch_assets(tag, sorted(prefetch_paths), self.http.get)

        # Phase 2: full applicable-asset scoring on finalists
        scored = self.score_tags_parallel(finalists, live_map, None)
        scored.sort(
            key=lambda x: (x.weighted_score, x.match_count, x.confidence_pct),
            reverse=True,
        )
        self.find_unique_discriminators(scored, live_map)

        detected = scored[0].tag if scored else None
        conf_pct = scored[0].confidence_pct if scored else 0.0
        unique = scored[0].unique_discriminators if scored else []
        conf_label = self.confidence_label(
            conf_pct,
            len(unique),
            scored[0].match_count if scored else 0,
        )

        # Prefer generator/readme if it matches a top candidate
        disclosed = html_ind.get("generator_version")
        for s in supplementary:
            if s.get("readme_version"):
                disclosed = disclosed or s["readme_version"]
        if disclosed and scored:
            for s in scored[:5]:
                if s.tag == disclosed or s.tag.startswith(disclosed.rstrip(".0")):
                    detected = s.tag
                    break

        if detected:
            mismatches = self.mismatch_analysis(detected, live_map)
            if mismatches:
                notes.append(
                    f"{len(mismatches)} asset(s) differ from stock {detected} - "
                    "likely CDN/cache/minor customization"
                )
        else:
            mismatches = []

        themes_detected: list[dict[str, Any]] = []
        mu_plugins_detected: list[dict[str, Any]] = []
        crawl_stats: dict[str, Any] = {}
        if self.crawl:
            crawl_plugins, themes_detected, mu_plugins_detected, crawl_stats, crawl_notes = (
                self.run_extension_crawl(html)
            )
            plugins = crawl_plugins
            notes.extend(crawl_notes)
            limitations.append(
                "Crawl discovers extensions referenced in HTML; "
                "must-use or admin-only plugins may still be missed"
            )
            limitations.append(
                "Version resolution probes readme.txt, style.css, and plugin headers; "
                "blocked files yield unknown version"
            )

        vulnerabilities: list[dict[str, Any]] = []
        if self.check_vulns:
            vulnerabilities = scan_vulnerabilities(
                detected, plugins, themes_detected, self.http.get
            )
            if vulnerabilities:
                notes.append(f"Advisory lookup: {len(vulnerabilities)} potential issue(s)")

        top_candidates = [
            {
                "tag": s.tag,
                "match_count": s.match_count,
                "total_assets": s.total_assets,
                "weighted_score": s.weighted_score,
                "confidence_pct": s.confidence_pct,
                "matched_assets": s.matched,
                "missing_assets": s.missing,
                "skipped_assets": s.skipped,
                "unique_discriminators": s.unique_discriminators,
            }
            for s in scored[:5]
        ]

        return FingerprintReport(
            target=self.base_url,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            detected_version=detected,
            detected_era=era,
            confidence=conf_label,
            confidence_pct=conf_pct,
            tags_compared=len(candidate_tags),
            supported_range=SUPPORTED_VERSION_RANGE,
            top_candidates=top_candidates,
            assets=[asdict(a) for a in assets if a.md5],
            html_indicators=html_ind,
            supplementary=supplementary,
            plugins_detected=plugins,
            themes_detected=themes_detected,
            mu_plugins_detected=mu_plugins_detected,
            crawl_enabled=self.crawl,
            crawl_stats=crawl_stats,
            vulnerabilities=vulnerabilities,
            notes=notes,
            limitations=limitations,
            asset_mismatches=mismatches,
            scan_profile=self.scan_profile,
            request_stats=self.http.stats.to_dict(),
            cache_stats=self.asset_cache.to_dict(),
            tool_version=TOOL_VERSION,
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WordPress core, plugin and theme version detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--url", help="WordPress site base URL")
    p.add_argument("--config", "-c", help="JSON config file (CLI overrides config)")
    p.add_argument("--output", "-o", help="Write JSON report to this path")
    p.add_argument("--markdown", "-m", help="Write Markdown report to this path")
    p.add_argument("--html", help="Write HTML report to this path")
    p.add_argument("--sarif", help="Write SARIF report for CI (GitHub Code Scanning)")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="HTTP User-Agent")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout (seconds)")
    p.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Parallel asset fetch workers (use 1 with --gentle)",
    )
    p.add_argument(
        "--tag-workers", type=int, default=8, help="Parallel tag scoring workers"
    )
    p.add_argument(
        "--target-delay",
        type=float,
        default=0.75,
        help="Minimum seconds between target-site requests (default: 0.75)",
    )
    p.add_argument(
        "--github-delay",
        type=float,
        default=0.05,
        help="Minimum seconds between GitHub requests (default: 0.05)",
    )
    p.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Retries for transient SSL/network errors (default: 3)",
    )
    p.add_argument(
        "--retry-backoff",
        type=float,
        default=2.0,
        help="Exponential backoff base for retries (default: 2.0)",
    )
    p.add_argument(
        "--relaxed-ssl",
        action="store_true",
        help="Use relaxed TLS cipher policy (helps some CDNs/WAFs)",
    )
    p.add_argument(
        "--gentle",
        action="store_true",
        help="Stealth mode: slow sequential target requests, retries, minimal probes",
    )
    p.add_argument(
        "--minimal-probes",
        action="store_true",
        help="Skip heavy/sensitive supplementary paths (debug.log, wp-json, feed)",
    )
    p.add_argument(
        "--sequential",
        action="store_true",
        help="Fetch target assets one-by-one (no parallel burst)",
    )
    p.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl site pages to discover all plugins/themes and resolve versions",
    )
    p.add_argument(
        "--crawl-workers",
        type=int,
        default=2,
        help="Parallel workers for page crawl and version probes (default: 2)",
    )
    p.add_argument(
        "--crawl-max-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl when --crawl is enabled (default: 50)",
    )
    p.add_argument(
        "--crawl-max-depth",
        type=int,
        default=3,
        help="Maximum link depth from start URL during crawl (default: 3)",
    )
    p.add_argument(
        "--crawl-delay",
        type=float,
        default=None,
        help="Seconds between crawl requests (default: target-delay or robots crawl-delay)",
    )
    p.add_argument(
        "--enumerate-plugins",
        action="store_true",
        help="With --crawl: probe common plugin slugs from built-in wordlist",
    )
    p.add_argument(
        "--ignore-robots",
        action="store_true",
        help="Ignore robots.txt during crawl (authorized pentest only)",
    )
    p.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra HTTP header (repeatable), e.g. --header 'Cookie: session=1'",
    )
    p.add_argument("--cookie", help="Cookie header value for authenticated scans")
    p.add_argument(
        "--max-requests",
        type=int,
        default=0,
        help="Cap total HTTP requests (0 = unlimited)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable SQLite reference cache (~/.cache/wp-core-fingerprint)",
    )
    p.add_argument(
        "--check-vulns",
        action="store_true",
        help="Query WPVulnerability.net advisories for core/plugins/themes",
    )
    p.add_argument(
        "--min-confidence",
        choices=["insufficient", "low", "medium", "high"],
        default="insufficient",
        help="Exit code 2 if confidence below this level (default: insufficient = never fail)",
    )
    p.add_argument(
        "--min-major",
        type=int,
        default=1,
        help="Minimum WP major version tag to compare (default: 1 = all releases)",
    )
    p.add_argument(
        "--quick",
        action="store_true",
        help="Fast mode: compare only recent 6.9.x / 7.x tags",
    )
    p.add_argument(
        "--tag-limit",
        type=int,
        default=0,
        help="Limit GitHub tags after era filter (0 = no limit)",
    )
    p.add_argument(
        "--phase1-limit",
        type=int,
        default=60,
        help="Top N tags from phase-1 to fully score in phase-2",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress console summary")
    return p.parse_args(argv)


def print_summary(r: FingerprintReport) -> None:
    def safe(s: str) -> str:
        return s.encode("ascii", errors="replace").decode("ascii")

    print("=" * 60)
    print("WordPress Core, Plugin & Theme Detection")
    print("=" * 60)
    print(f"Target:     {r.target}")
    print(f"Detected:   {r.detected_version or 'unknown'}")
    print(f"Era:        {r.detected_era or 'unknown'}")
    print(f"Profile:    {r.scan_profile}")
    print(f"Confidence: {r.confidence} ({r.confidence_pct}%)")
    if r.request_stats:
        rs = r.request_stats
        print(
            f"Requests:   target={rs.get('target_requests', 0)} "
            f"github={rs.get('github_requests', 0)} "
            f"retries={rs.get('retries', 0)} "
            f"throttle={rs.get('throttle_sleep_s', 0)}s"
        )
    print(f"Tags:       {r.tags_compared} compared ({r.supported_range})")
    print()
    if r.top_candidates:
        print("Top candidates:")
        for c in r.top_candidates[:3]:
            ud = c.get("unique_discriminators") or []
            extra = f" [unique: {', '.join(ud)}]" if ud else ""
            print(
                f"  {c['tag']}: {c['match_count']}/{c['total_assets']} "
                f"({c['confidence_pct']}%){extra}"
            )
    if r.crawl_enabled:
        print(f"\nCrawl:      {r.crawl_stats.get('pages_success', 0)} pages, "
              f"{r.crawl_stats.get('plugins_discovered', 0)} plugins, "
              f"{r.crawl_stats.get('themes_discovered', 0)} themes")
        if r.plugins_detected:
            print("Plugins:")
            for p in r.plugins_detected[:8]:
                print(
                    f"  {p['slug']}: {p.get('version') or 'unknown'} "
                    f"({p.get('version_confidence', '?')})"
                )
        if r.themes_detected:
            print("Themes:")
            for t in r.themes_detected[:5]:
                active = " [active]" if t.get("active") else ""
                print(
                    f"  {t['slug']}: {t.get('version') or 'unknown'} "
                    f"({t.get('version_confidence', '?')}){active}"
                )
    elif r.plugins_detected:
        print(f"\nPlugins (homepage): {len(r.plugins_detected)} detected")
        for p in r.plugins_detected[:5]:
            print(f"  {p['slug']}: {p.get('version_hint', '?')}")
    if r.vulnerabilities:
        print(f"\nVulns:      {len(r.vulnerabilities)} advisory hit(s)")
        for v in r.vulnerabilities[:5]:
            print(f"  [{v.get('severity', '?')}] {v.get('id')}: {safe(v.get('title', '')[:60])}")
    if r.cache_stats.get("hits"):
        print(f"Cache:      {r.cache_stats.get('hits', 0)} hits / {r.cache_stats.get('misses', 0)} misses")
    if r.notes:
        print("\nNotes:")
        for n in r.notes[:6]:
            print(f"  - {safe(n)}")
    print("=" * 60)


def _parse_headers(header_args: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in header_args:
        if ":" not in h:
            continue
        name, value = h.split(":", 1)
        out[name.strip()] = value.strip()
    return out


def _confidence_meets(actual: str, minimum: str) -> bool:
    return CONFIDENCE_RANK.get(actual, 0) >= CONFIDENCE_RANK.get(minimum, 0)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.config:
        cfg = load_config(args.config)
        apply_config_defaults(args, cfg)
    if not args.url:
        print("ERROR: --url is required (or set url in --config)", file=sys.stderr)
        return EXIT_ERROR

    extra_headers = _parse_headers(args.header or [])
    fp = WPCoreFingerprinter(
        base_url=args.url,
        user_agent=args.user_agent,
        timeout=args.timeout,
        workers=args.workers,
        tag_workers=args.tag_workers,
        min_major=args.min_major,
        quick=args.quick,
        tag_limit=args.tag_limit,
        phase1_limit=args.phase1_limit,
        target_delay=args.target_delay,
        github_delay=args.github_delay,
        max_retries=args.max_retries,
        retry_backoff=args.retry_backoff,
        relaxed_ssl=args.relaxed_ssl,
        gentle=args.gentle,
        minimal_probes=args.minimal_probes,
        sequential_target=args.sequential,
        crawl=args.crawl,
        crawl_workers=args.crawl_workers,
        crawl_max_pages=args.crawl_max_pages,
        crawl_max_depth=args.crawl_max_depth,
        crawl_delay=args.crawl_delay,
        enumerate_plugins=args.enumerate_plugins,
        ignore_robots=args.ignore_robots,
        proxy=args.proxy,
        extra_headers=extra_headers or None,
        cookie=args.cookie,
        use_cache=not args.no_cache,
        check_vulns=args.check_vulns,
        max_requests=args.max_requests,
    )
    t0 = time.time()
    try:
        report = fp.run()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        fp.asset_cache.close()

    if not args.quiet:
        print_summary(report)
        print(f"Elapsed: {time.time() - t0:.1f}s")

    payload = report_to_json(report)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"JSON report: {out}")

    if args.markdown:
        md = Path(args.markdown)
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(report_to_markdown(report), encoding="utf-8")
        if not args.quiet:
            print(f"Markdown report: {md}")

    if args.html:
        hp = Path(args.html)
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(report_to_html(report), encoding="utf-8")
        if not args.quiet:
            print(f"HTML report: {hp}")

    if args.sarif:
        write_sarif(report, args.sarif)
        if not args.quiet:
            print(f"SARIF report: {args.sarif}")

    if not _confidence_meets(report.confidence, args.min_confidence):
        return EXIT_LOW_CONFIDENCE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

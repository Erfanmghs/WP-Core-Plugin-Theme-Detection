"""Site crawler for discovering WordPress plugins and themes across pages."""
from __future__ import annotations

import heapq
import importlib.resources
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from itertools import count
from typing import Any, Callable
from urllib.parse import urljoin, urlparse, urlunparse

from wp_core_fingerprint.extensions import (
    ExtensionRecord,
    extract_slugs_from_html,
    extract_version_hints_from_html,
    merge_records,
    resolve_all_extensions,
)
from wp_core_fingerprint.robots import RobotsRules, fetch_robots

HttpGet = Callable[[str, str], tuple[int | None, bytes, dict[str, str], str | None]]

HREF_RE = re.compile(
    r"""<(?:a|link)[^>]+(?:href)=["']([^"'#]+)["']""",
    re.I,
)
SRC_RE = re.compile(
    r"""<(?:script|img|iframe|source)[^>]+(?:src)=["']([^"'#]+)["']""",
    re.I,
)
LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)
STYLESHEET_THEME_RE = re.compile(
    r"wp-content/themes/([a-z0-9_-]+)/(?:[^\"']+\.css)", re.I
)

SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".zip", ".rar", ".7z",
})
SKIP_PATH_PARTS = re.compile(
    r"(?:wp-admin|wp-login|xmlrpc\.php|wp-cron\.php|/trackback/?$)",
    re.I,
)

MU_PLUGIN_CANDIDATES = (
    "bedrock-autoloader.php",
    "health-check-troubleshooting-mode.php",
    "wp-migrate-db-pro-compatibility.php",
    "kinsta-mu-plugins.php",
    "sso.php",
)


@dataclass
class CrawlStats:
    pages_requested: int = 0
    pages_success: int = 0
    pages_failed: int = 0
    pages_skipped_robots: int = 0
    sitemap_urls: int = 0
    wp_json_urls: int = 0
    enumerated_plugins: int = 0
    unique_links_seen: int = 0
    plugins_discovered: int = 0
    themes_discovered: int = 0
    mu_plugins_discovered: int = 0
    version_resolved: int = 0
    version_unresolved: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass
class CrawlResult:
    plugins: list[dict[str, Any]] = field(default_factory=list)
    themes: list[dict[str, Any]] = field(default_factory=list)
    mu_plugins: list[dict[str, Any]] = field(default_factory=list)
    stats: CrawlStats = field(default_factory=CrawlStats)
    notes: list[str] = field(default_factory=list)


def load_plugin_wordlist() -> list[str]:
    try:
        pkg = importlib.resources.files("wp_core_fingerprint") / "data" / "common-plugins.txt"
        text = pkg.read_text(encoding="utf-8")
    except Exception:
        return []
    return [ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


class WordPressExtensionCrawler:
    def __init__(
        self,
        base_url: str,
        http_get: HttpGet,
        max_pages: int = 50,
        max_depth: int = 3,
        workers: int = 2,
        crawl_delay: float | None = None,
        enumerate_plugins: bool = False,
        ignore_robots: bool = False,
        plugin_wordlist: list[str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        parsed = urlparse(self.base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.base_path = parsed.path or "/"
        self.http_get = http_get
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)
        self.workers = max(1, workers)
        self.crawl_delay = crawl_delay
        self.enumerate_plugins = enumerate_plugins
        self.ignore_robots = ignore_robots
        self.plugin_wordlist = plugin_wordlist or load_plugin_wordlist()
        self._visited: set[str] = set()
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], ExtensionRecord] = {}
        self._links_seen: set[str] = set()
        self._robots: RobotsRules | None = None
        self._active_theme_hint: str | None = None
        self._counter = count()

    def url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _get(self, url: str) -> tuple[int | None, bytes, dict[str, str], str | None]:
        delay = self.crawl_delay
        if self._robots and self._robots.crawl_delay and delay is None:
            delay = self._robots.crawl_delay
        return self.http_get(url, "GET", delay) if delay else self.http_get(url)

    def _normalize(self, href: str, from_url: str) -> str | None:
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            return None
        absolute = urljoin(from_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return None
        if f"{parsed.scheme}://{parsed.netloc}" != self.origin:
            return None

        path = parsed.path or "/"
        if self.base_path != "/":
            base = self.base_path.rstrip("/")
            if "/wp-content/" not in path and not path.startswith(base):
                return None

        lower = path.lower()
        for ext in SKIP_EXTENSIONS:
            if lower.endswith(ext):
                return None
        if SKIP_PATH_PARTS.search(path):
            return None

        clean = urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/") if path != "/" else path, "", "", ""))
        if not self.ignore_robots and self._robots and not self._robots.allowed(clean):
            return None
        return clean

    def _link_priority(self, url: str) -> int:
        path = urlparse(url).path.lower()
        if any(x in path for x in ("/category/", "/tag/", "/author/", "/page/", "/20")):
            return 1
        if path.endswith("/feed") or "/feed/" in path:
            return 9
        return 3

    def _extract_links(self, html: str, page_url: str) -> list[str]:
        links: list[str] = []
        for pattern in (HREF_RE, SRC_RE):
            for m in pattern.finditer(html):
                norm = self._normalize(m.group(1).strip(), page_url)
                if norm:
                    links.append(norm)
        return links

    def _ingest_html(self, html: str, page_url: str) -> None:
        plugins, themes, mu = extract_slugs_from_html(html)
        plugin_hints, theme_hints, plugin_php = extract_version_hints_from_html(html)

        for slug in plugins:
            rec = merge_records(self._records, slug, "plugin", page_url)
            for hint in plugin_hints.get(slug, []):
                if hint not in rec.html_version_hints:
                    rec.html_version_hints.append(hint)
            for php_file in plugin_php.get(slug, []):
                if php_file not in rec.candidate_php_files:
                    rec.candidate_php_files.append(php_file)

        for slug in themes:
            rec = merge_records(self._records, slug, "theme", page_url)
            for hint in theme_hints.get(slug, []):
                if hint not in rec.html_version_hints:
                    rec.html_version_hints.append(hint)

        for mu_file in mu:
            merge_records(self._records, mu_file, "mu-plugin", page_url)

        for m in re.finditer(r"\btheme-([a-z0-9_-]+)\b", html, re.I):
            merge_records(self._records, m.group(1).lower(), "theme", page_url)

        sm = STYLESHEET_THEME_RE.search(html)
        if sm:
            self._active_theme_hint = sm.group(1).lower()

    def _fetch_page(self, url: str) -> tuple[str | None, str | None]:
        status, body, _, err = self._get(url)
        if err or status != 200 or not body:
            return None, err or f"HTTP {status}"
        ctype = ""
        return body.decode("utf-8", errors="ignore"), None

    def _discover_sitemap_urls(self) -> list[str]:
        seeds: list[str] = []
        for path in ("sitemap_index.xml", "wp-sitemap.xml", "sitemap.xml", "sitemap-index.xml"):
            url = self.url(path)
            status, body, _, _ = self._get(url)
            if status != 200 or not body:
                continue
            text = body.decode("utf-8", errors="ignore")
            locs = LOC_RE.findall(text)
            for loc in locs[:300]:
                norm = self._normalize(loc.strip(), url)
                if norm:
                    seeds.append(norm)
            if locs:
                break
        return seeds

    def _discover_wp_json_urls(self) -> list[str]:
        urls: list[str] = []
        for endpoint in (
            "wp-json/wp/v2/pages?per_page=100&_fields=link",
            "wp-json/wp/v2/posts?per_page=100&_fields=link",
        ):
            api_url = self.url(endpoint)
            status, body, _, _ = self._get(api_url)
            if status != 200 or not body:
                continue
            try:
                items = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and item.get("link"):
                    norm = self._normalize(item["link"], api_url)
                    if norm:
                        urls.append(norm)
        return urls

    def _probe_mu_plugins(self) -> None:
        for fname in MU_PLUGIN_CANDIDATES:
            path = f"wp-content/mu-plugins/{fname}"
            status, body, _, _ = self._get(self.url(path))
            if status == 200 and body:
                merge_records(self._records, fname, "mu-plugin", "mu-probe")

    def _enumerate_plugins(self, stats: CrawlStats) -> None:
        if not self.enumerate_plugins or not self.plugin_wordlist:
            return

        def probe(slug: str) -> str | None:
            for suffix in ("readme.txt", f"{slug}.php"):
                path = f"wp-content/plugins/{slug}/{suffix}"
                status, body, _, _ = self._get(self.url(path))
                if status == 200 and body and len(body) > 20:
                    return slug
            return None

        found = 0
        with ThreadPoolExecutor(max_workers=min(self.workers, 4)) as pool:
            futures = {pool.submit(probe, slug): slug for slug in self.plugin_wordlist}
            for fut in as_completed(futures):
                slug = fut.result()
                if slug:
                    merge_records(self._records, slug, "plugin", "enumeration")
                    found += 1
        stats.enumerated_plugins = found

    def _process_url(
        self, url: str, depth: int
    ) -> tuple[str, int, str | None, str | None, list[str]]:
        html, err = self._fetch_page(url)
        links: list[str] = []
        if html:
            links = self._extract_links(html, url)
        return url, depth, html, err, links

    def crawl_pages(self, stats: CrawlStats) -> None:
        if not self.ignore_robots:
            self._robots = fetch_robots(self.base_url, self._get)

        start = self.base_url.rstrip("/") or self.origin
        heap: list[tuple[int, int, str, int]] = []
        heapq.heappush(heap, (0, next(self._counter), start, 0))

        sitemap_seeds = self._discover_sitemap_urls()
        stats.sitemap_urls = len(sitemap_seeds)
        for seed in sitemap_seeds[:300]:
            if seed not in self._visited:
                heapq.heappush(heap, (0, next(self._counter), seed, 1))

        wp_json = self._discover_wp_json_urls()
        stats.wp_json_urls = len(wp_json)
        for seed in wp_json[:100]:
            if seed not in self._visited:
                heapq.heappush(heap, (0, next(self._counter), seed, 1))

        fetched = 0
        while heap and fetched < self.max_pages:
            batch: list[tuple[str, int]] = []
            while heap and len(batch) < self.workers and fetched + len(batch) < self.max_pages:
                _prio, _seq, url, depth = heapq.heappop(heap)
                with self._lock:
                    if url in self._visited:
                        continue
                    if not self.ignore_robots and self._robots and not self._robots.allowed(url):
                        stats.pages_skipped_robots += 1
                        continue
                    self._visited.add(url)
                if depth > self.max_depth:
                    continue
                batch.append((url, depth))

            if not batch:
                continue

            if self.workers <= 1:
                results = [self._process_url(u, d) for u, d in batch]
            else:
                results = []
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    futures = {pool.submit(self._process_url, u, d): (u, d) for u, d in batch}
                    for fut in as_completed(futures):
                        results.append(fut.result())

            for page_url, depth, html, err, links in results:
                stats.pages_requested += 1
                fetched += 1
                if err or html is None:
                    stats.pages_failed += 1
                    continue
                stats.pages_success += 1
                self._ingest_html(html, page_url)
                if depth >= self.max_depth:
                    continue
                for link in links:
                    self._links_seen.add(link)
                    with self._lock:
                        if link not in self._visited:
                            prio = self._link_priority(link)
                            heapq.heappush(heap, (prio, next(self._counter), link, depth + 1))

        stats.unique_links_seen = len(self._links_seen)

    def _mark_active_themes(self) -> None:
        if self._active_theme_hint:
            for (kind, slug), rec in self._records.items():
                if kind == "theme":
                    rec.active = slug == self._active_theme_hint
            return
        theme_hits: dict[str, int] = {}
        for (kind, slug), rec in self._records.items():
            if kind == "theme":
                theme_hits[slug] = len(rec.pages_found)
        if not theme_hits:
            return
        active_slug = max(theme_hits, key=theme_hits.get)
        for (kind, slug), rec in self._records.items():
            if kind == "theme":
                rec.active = slug == active_slug

    def run(self, initial_html: str | None = None) -> CrawlResult:
        stats = CrawlStats()
        notes: list[str] = []

        start = self.base_url.rstrip("/") or self.origin
        if initial_html:
            self._visited.add(start)
            self._ingest_html(initial_html, start)

        self.crawl_pages(stats)
        self._probe_mu_plugins()
        self._enumerate_plugins(stats)
        self._mark_active_themes()

        def crawl_get(url: str, method: str = "GET") -> tuple[int | None, bytes, dict[str, str], str | None]:
            return self._get(url)

        resolved = resolve_all_extensions(
            self._records,
            self.url,
            crawl_get,
            workers=self.workers,
        )

        plugins, themes, mu_plugins = [], [], []
        for rec in resolved:
            d = rec.to_dict()
            if rec.version:
                stats.version_resolved += 1
            else:
                stats.version_unresolved += 1
            if rec.kind == "plugin":
                plugins.append(d)
            elif rec.kind == "theme":
                themes.append(d)
            else:
                mu_plugins.append(d)

        stats.plugins_discovered = len(plugins)
        stats.themes_discovered = len(themes)
        stats.mu_plugins_discovered = len(mu_plugins)

        notes.append(
            f"Crawl: {stats.pages_success}/{stats.pages_requested} pages OK "
            f"(robots skipped {stats.pages_skipped_robots})"
        )
        if stats.sitemap_urls:
            notes.append(f"Sitemap seeds: {stats.sitemap_urls}")
        if stats.wp_json_urls:
            notes.append(f"wp-json REST seeds: {stats.wp_json_urls}")
        if stats.enumerated_plugins:
            notes.append(f"Plugin enumeration confirmed {stats.enumerated_plugins} extra plugins")
        notes.append(
            f"Inventory: {stats.plugins_discovered} plugins, {stats.themes_discovered} themes, "
            f"{stats.mu_plugins_discovered} mu-plugins | "
            f"versions resolved {stats.version_resolved}/{len(resolved)}"
        )

        return CrawlResult(plugins=plugins, themes=themes, mu_plugins=mu_plugins, stats=stats, notes=notes)

"""Rate-limited HTTP client with proxy, retries, circuit breaker, request budget."""
from __future__ import annotations

import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

TRANSIENT_MARKERS = (
    "UNEXPECTED_EOF",
    "EOF occurred",
    "Connection reset",
    "timed out",
    "Temporary failure",
    "429",
    "503",
    "502",
    "504",
)

RETRY_AFTER_RE = re.compile(r"^\s*(\d+)\s*$")


@dataclass
class RequestStats:
    target_requests: int = 0
    github_requests: int = 0
    retries: int = 0
    throttle_sleep_s: float = 0.0
    circuit_opens: int = 0
    budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_requests": self.target_requests,
            "github_requests": self.github_requests,
            "retries": self.retries,
            "throttle_sleep_s": round(self.throttle_sleep_s, 2),
            "circuit_opens": self.circuit_opens,
            "budget_exhausted": self.budget_exhausted,
            "errors": self.errors[:15],
        }


class RateLimitedHttp:
    """Paced HTTP with WAF-friendly retries, optional proxy and request cap."""

    def __init__(
        self,
        user_agent: str,
        timeout: int = 30,
        target_delay: float = 0.75,
        github_delay: float = 0.05,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
        relaxed_ssl: bool = False,
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
        cookie: str | None = None,
        max_requests: int = 0,
        circuit_threshold: int = 8,
        circuit_pause_s: float = 45.0,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.target_delay = max(0.0, target_delay)
        self.github_delay = max(0.0, github_delay)
        self.max_retries = max(1, max_retries)
        self.retry_backoff = max(1.0, retry_backoff)
        self.relaxed_ssl = relaxed_ssl
        self.max_requests = max(0, max_requests)
        self.circuit_threshold = circuit_threshold
        self.circuit_pause_s = circuit_pause_s
        self.stats = RequestStats()
        self._lock = threading.Lock()
        self._last_target_at = 0.0
        self._last_github_at = 0.0
        self._target_fail_streak = 0
        self._circuit_open_until = 0.0
        self._total_requests = 0
        self.ctx = self._build_ssl_context()
        self._extra_headers = dict(extra_headers or {})
        if cookie:
            self._extra_headers.setdefault("Cookie", cookie)
        self._opener = self._build_opener(proxy)

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.relaxed_ssl:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except ssl.SSLError:
                pass
        return ctx

    def _build_opener(self, proxy: str | None) -> urllib.request.OpenerDirector:
        handlers: list[Any] = [urllib.request.HTTPSHandler(context=self.ctx)]
        if proxy:
            handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        return urllib.request.build_opener(*handlers)

    def _is_github(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        return "github" in host or "githubusercontent" in host

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": self.user_agent}
        h.update(self._extra_headers)
        if self._is_github("") is False:
            pass
        return h

    def _request_headers(self, url: str) -> dict[str, str]:
        h = {"User-Agent": self.user_agent}
        h.update(self._extra_headers)
        if self._is_github(url):
            h.setdefault("Accept", "application/vnd.github+json")
        return h

    def _throttle(self, url: str, override_delay: float | None = None) -> None:
        delay = override_delay
        if delay is None:
            delay = self.github_delay if self._is_github(url) else self.target_delay
        if delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            last = self._last_github_at if self._is_github(url) else self._last_target_at
            wait = delay - (now - last)
            if wait > 0:
                time.sleep(wait)
                self.stats.throttle_sleep_s += wait
                now = time.monotonic()
            if self._is_github(url):
                self._last_github_at = now
            else:
                self._last_target_at = now

    def _wait_circuit(self) -> None:
        now = time.monotonic()
        if now < self._circuit_open_until:
            wait = self._circuit_open_until - now
            time.sleep(wait)
            self.stats.throttle_sleep_s += wait

    def _transient(self, err: str | None, status: int | None) -> bool:
        if status in (429, 502, 503, 504):
            return True
        if not err:
            return False
        return any(m in err for m in TRANSIENT_MARKERS)

    def _parse_retry_after(self, headers: dict[str, str]) -> float | None:
        raw = headers.get("retry-after")
        if not raw:
            return None
        m = RETRY_AFTER_RE.match(raw)
        if m:
            return float(m.group(1))
        return None

    def _budget_ok(self) -> bool:
        if self.max_requests <= 0:
            return True
        with self._lock:
            if self._total_requests >= self.max_requests:
                self.stats.budget_exhausted = True
                return False
            return True

    def _count_request(self, url: str) -> None:
        with self._lock:
            self._total_requests += 1
            if self._is_github(url):
                self.stats.github_requests += 1
            else:
                self.stats.target_requests += 1

    def _note_target_result(self, ok: bool) -> None:
        if ok:
            self._target_fail_streak = 0
            return
        self._target_fail_streak += 1
        if self._target_fail_streak >= self.circuit_threshold:
            self._circuit_open_until = time.monotonic() + self.circuit_pause_s
            self.stats.circuit_opens += 1
            self._target_fail_streak = 0

    def get(
        self,
        url: str,
        method: str = "GET",
        delay_override: float | None = None,
    ) -> tuple[int | None, bytes, dict[str, str], str | None]:
        if not self._budget_ok():
            return None, b"", {}, "Request budget exhausted (--max-requests)"

        last_err: str | None = None
        is_target = not self._is_github(url)

        for attempt in range(self.max_retries):
            if is_target:
                self._wait_circuit()
            self._throttle(url, delay_override)

            req = urllib.request.Request(url, method=method, headers=self._request_headers(url))
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    self._count_request(url)
                    if is_target:
                        self._note_target_result(True)
                    return resp.status, body, headers, None
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read()
                except Exception:
                    body = b""
                headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                self._count_request(url)
                if is_target:
                    self._note_target_result(False)
                if self._transient(str(exc), exc.code) and attempt + 1 < self.max_retries:
                    self.stats.retries += 1
                    ra = self._parse_retry_after(headers)
                    time.sleep(ra if ra else self.retry_backoff ** attempt)
                    continue
                return exc.code, body, headers, None
            except Exception as exc:
                last_err = str(exc)
                self._count_request(url)
                if is_target:
                    self._note_target_result(False)
                if self._transient(last_err, None) and attempt + 1 < self.max_retries:
                    self.stats.retries += 1
                    time.sleep(self.retry_backoff ** attempt)
                    continue
                if len(self.stats.errors) < 15:
                    self.stats.errors.append(f"{url}: {last_err}")
                return None, b"", {}, last_err
        return None, b"", {}, last_err

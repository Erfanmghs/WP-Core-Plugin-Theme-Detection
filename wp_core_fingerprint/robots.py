"""Minimal robots.txt parser for crawl politeness."""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlparse

HttpGet = Callable[[str, str], tuple[int | None, bytes, dict[str, str], str | None]]

USER_AGENT_ALL = "*"


class RobotsRules:
    def __init__(self) -> None:
        self.disallow: list[str] = []
        self.allow: list[str] = []
        self.crawl_delay: float | None = None
        self._active_ua: str | None = None

    def feed(self, line: str) -> None:
        line = line.strip()
        if not line or line.startswith("#"):
            return
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip().lower()
            self._active_ua = ua
            return
        if self._active_ua not in (USER_AGENT_ALL, None) and "wp-fingerprint" not in self._active_ua:
            return
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                self.disallow.append(path)
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                self.allow.append(path)
        elif line.lower().startswith("crawl-delay:"):
            try:
                self.crawl_delay = float(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    def allowed(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        for prefix in self.disallow:
            if prefix == "/":
                return False
            if path.startswith(prefix):
                for allow_prefix in self.allow:
                    if path.startswith(allow_prefix):
                        return True
                return False
        return True


def fetch_robots(base_url: str, http_get: HttpGet) -> RobotsRules:
    rules = RobotsRules()
    robots_url = base_url.rstrip("/") + "/robots.txt"
    status, body, _, err = http_get(robots_url)
    if err or status != 200 or not body:
        return rules
    text = body.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        rules.feed(line)
    return rules

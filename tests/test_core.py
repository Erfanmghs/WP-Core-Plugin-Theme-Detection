import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_core_fingerprint.cache import AssetCache
from wp_core_fingerprint.config import load_config
from wp_core_fingerprint.extensions import (
    parse_header_version,
    parse_readme_version,
    parse_style_css,
    _pick_version,
    ExtensionRecord,
    _add_source,
)
from wp_core_fingerprint.robots import RobotsRules
from wp_core_fingerprint.tags import detect_era, is_stable_tag, parse_version


class TestTags(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(parse_version("7.0.3"), (7, 0, 3, 0))

    def test_stable_tag(self):
        self.assertTrue(is_stable_tag("6.4.2"))
        self.assertFalse(is_stable_tag("6.4-RC1"))

    def test_detect_era_modern(self):
        live = {"hooks.min.js", "components.min.js"}
        self.assertEqual(detect_era(live), "modern")


class TestExtensions(unittest.TestCase):
    def test_readme_stable(self):
        text = "=== Plugin ===\nStable tag: 2.1.0\n"
        self.assertEqual(parse_readme_version(text), "2.1.0")

    def test_plugin_header(self):
        text = "/*\nPlugin Name: Test\nVersion: 1.2.3\n*/"
        self.assertEqual(parse_header_version(text), "1.2.3")

    def test_style_css(self):
        css = "/*\nTheme Name: Astra\nVersion: 4.5.1\nTemplate: parent\n*/"
        meta = parse_style_css(css)
        self.assertEqual(meta["version"], "4.5.1")
        self.assertEqual(meta["parent"], "parent")

    def test_pick_version_confirmed(self):
        rec = ExtensionRecord(slug="x", kind="plugin")
        _add_source(rec, "readme.txt", "1.0.0", 95)
        _pick_version(rec)
        self.assertEqual(rec.version, "1.0.0")
        self.assertEqual(rec.version_confidence, "confirmed")


class TestRobots(unittest.TestCase):
    def test_disallow(self):
        rules = RobotsRules()
        rules.feed("User-agent: *")
        rules.feed("Disallow: /wp-admin/")
        self.assertFalse(rules.allowed("https://ex.com/wp-admin/"))
        self.assertTrue(rules.allowed("https://ex.com/blog/post"))


class TestConfig(unittest.TestCase):
    def test_load_config_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(b"\xef\xbb\xbf" + b'{"url": "https://example.com/", "gentle": true}')
            cfg = load_config(path)
            self.assertEqual(cfg["url"], "https://example.com/")
            self.assertTrue(cfg["gentle"])


class TestCache(unittest.TestCase):
    def test_asset_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = AssetCache(cache_dir=Path(tmp), enabled=True)
            cache.put_asset("7.0.3", "wp-includes/version.php", b"test")
            self.assertEqual(cache.get_asset("7.0.3", "wp-includes/version.php"), b"test")
            cache.put_tag_list(["7.0.3", "7.0.2"])
            tags = cache.get_tag_list()
            self.assertIn("7.0.3", tags or [])
            cache.close()


if __name__ == "__main__":
    unittest.main()

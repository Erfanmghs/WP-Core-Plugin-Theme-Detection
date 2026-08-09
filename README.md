# WordPress Core, Plugin & Theme Detection
Remote fingerprinting for WordPress **core** (down to the patch) and, with `--crawl`, **plugins and themes** too. Built for sites where generator meta and readme are gone.

No login. No Ruby. No API token. Python 3.10+ and the standard library are enough.

---

## Why this exists

On a real pentest or audit, you often hit a WordPress site that has:

- no `<meta generator>`
- `readme.html` returning 404
- `version.php` returning an empty body (PHP runs server-side)

You still need the exact core version before you can say anything useful about CVEs. Guessing "probably 6.x" is not a finding.

This tool downloads public files from `wp-includes/`, hashes them, and compares them against **860+ official release tags** on GitHub. When several assets match one tag and one file only matches that tag among the top candidates, you get patch-level confidence even on hardened installs.

**WPScan** ([wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)) is the right tool for broad scanning: users, plugins, themes, and a large CVE database. But that database needs an API token (25 free lookups per day), and core detection there is heuristic. It will not MD5-compare your target against every stable GitHub release to prove why the answer is 7.0.3 and not 7.0.2.

Use both if you can: this tool for **exact core + evidence**, WPScan for **enumeration and CVE mapping**.

---

## Install and run

```bash
git clone https://github.com/Erfanmghs/WordPress-Core-Plugin-Theme-Detection.git
cd WordPress-Core-Plugin-Theme-Detection
pip install .
```

**Basic scan** (homepage + 19 core assets):

```bash
python -m wp_core_fingerprint --url https://example.com/blog/
```

**Production target** (slow, fewer WAF blocks):

```bash
python -m wp_core_fingerprint --url https://example.com/blog/ --gentle
```

**Save a report**:

```bash
python -m wp_core_fingerprint \
  --url https://example.com/blog/ \
  --gentle \
  --output report.json \
  --markdown report.md
```

**Plugins and themes** (optional, hits more pages):

```bash
python -m wp_core_fingerprint \
  --url https://example.com/blog/ \
  --gentle \
  --crawl \
  --enumerate-plugins \
  --output report.json
```

Through Burp:

```bash
python -m wp_core_fingerprint --url https://target/ --proxy http://127.0.0.1:8080 --gentle
```

Docker:

```bash
docker build -t wp-fingerprint .
docker run --rm wp-fingerprint --url https://example.com/ --gentle
```

Second run on the same machine is much faster: reference data is cached under `~/.cache/wp-core-fingerprint/`.

---

## Reading the output

Console summary shows the headline: detected version, confidence, top candidates.

**JSON** (`--output`) is what you want for real work. Focus on:

| Field | What it means |
|-------|----------------|
| `detected_version` | Best answer, e.g. `7.0.3` |
| `confidence` | `high` / `medium` / `low` / `insufficient` |
| `top_candidates` | Other close tags; if the gap is small, note it in your report |
| `top_candidates[].unique_discriminators` | Files that only match the winner among top tags. Strong evidence. |
| `asset_mismatches` | CDN or customization; common, does not always invalidate the result |
| `plugins_detected` / `themes_detected` | Present when `--crawl` is on, with `version` and `version_confidence` |
| `request_stats` | Retries and throttle time; useful if the target was flaky |

**Markdown** (`--markdown`) is ready to paste into a client report.

If you need CI to fail when the version is uncertain:

```bash
python -m wp_core_fingerprint --url https://staging/ --min-confidence medium
```

Exit code `2` means confidence was below your threshold.

Optional advisory hints (not a full CVE database):

```bash
python -m wp_core_fingerprint --url https://example.com/ --check-vulns --output report.json
```

---

## How core detection works (short version)

1. Fetch homepage and up to 19 static core files.
2. Figure out the era (legacy / 4.x / 5.x / 6–7.x) from what responded.
3. Score GitHub tags in two passes: fast anchors first, then full weighted MD5 match.
4. Pick the winner; use unique assets to separate close patches.

Works from WordPress **1.5 through 7.x**. Use `--quick` if you already know the site is on 6.9+ or 7.x.

---

## Flags worth knowing

| Flag | When |
|------|------|
| `--gentle` | WAF, CDN, or first touch on production |
| `--quick` | Modern WP only, faster |
| `--crawl` | Find plugins/themes used on inner pages |
| `--enumerate-plugins` | With `--crawl`: probe a built-in list of common plugin slugs |
| `--no-cache` | Force fresh GitHub fetches |
| `--config file.json` | Reuse settings; see `examples/scan-config.json` |

Full list: `python -m wp_core_fingerprint --help`

---

## Limits (honest)

- Admin-only plugins with no public HTML footprint will not appear.
- Blocked `readme.txt` / `style.css` means plugin/theme version may stay unknown.
- This is not user enumeration, not login testing, and not a replacement for WPScan's CVE database.
- Authorized testing only. Prefer `--gentle` on systems you do not own.

---

## License

MIT. See [LICENSE](LICENSE).

Maintained by [Erfanmghs](https://github.com/Erfanmghs).

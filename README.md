# WordPress Core, Plugin & Theme Detection

Remote fingerprinting for WordPress **core** (down to the patch) and, with `--crawl`, **plugins and themes** too. Built for hardened sites where generator meta, `readme.html`, and `version.php` no longer leak the version.

Passive only: public HTTP GET requests. No login, no Ruby, no API token for core detection.

**Package:** `wp-core-fingerprint` · **CLI:** `wp-fingerprint` · **Module:** `python3 -m wp_core_fingerprint`

---

## Features

| Area | What you get |
|------|----------------|
| **Core version** | MD5 fingerprint of up to 19 public `wp-includes/` assets vs **860+ official GitHub release tags** (WP 1.5 → 7.x) |
| **Patch-level evidence** | Weighted scoring, era detection, `unique_discriminators` that separate close patches (e.g. 7.0.2 vs 7.0.3) |
| **Plugin & theme inventory** | `--crawl` BFS over inner pages; version resolution via `readme.txt`, `style.css`, plugin headers |
| **Plugin enumeration** | `--enumerate-plugins` probes a built-in wordlist of common plugin slugs |
| **Advisory hints** | `--check-vulns` queries [WPVulnerability.net](https://www.wpvulnerability.net/) (no API key) |
| **Reports** | JSON (schema 3.0), Markdown, HTML, SARIF (GitHub Code Scanning) |
| **Production-safe pacing** | `--gentle` slow sequential requests, retries, circuit breaker, optional `--relaxed-ssl` |
| **CI integration** | `--min-confidence` exit code 2; `--sarif` for pipelines |
| **Config files** | JSON config (`examples/scan-config.json`); CLI overrides config |
| **Burp / proxy** | `--proxy`, `--cookie`, repeatable `--header` |
| **Caching** | SQLite cache at `~/.cache/wp-core-fingerprint/` (GitHub reference data) |
| **Docker** | Single-image container with `wp-fingerprint` entrypoint |

---

## Why this exists

On a real pentest or audit you often hit WordPress that has:

- no `<meta name="generator">`
- `readme.html` returning 404
- `wp-includes/version.php` returning an empty body (PHP executes server-side)

You still need the exact core version before CVE mapping means anything. Guessing "probably 6.x" is not a finding.

This tool compares public core file hashes against every stable release on GitHub. When several assets match one tag and one file only matches that tag among the top candidates, you get patch-level confidence even on hardened installs.

**WPScan** ([wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)) is excellent for broad scanning (users, plugins, themes, CVE DB) but needs an API token and uses heuristics for core. Use both when you can: this tool for **exact core + evidence**, WPScan for **enumeration and CVE mapping**.

---

## Requirements

- **Python 3.10+** (stdlib only; no pip dependencies at runtime)
- Network access to the target site and to `raw.githubusercontent.com` (reference tags)
- **Authorized testing only**

On Linux, `python` may not exist — use **`python3`**. On modern Debian/Ubuntu, install into a **virtual environment** (PEP 668 blocks system-wide `pip install`).

---

## Installation

### Linux / macOS (recommended: virtual environment)

```bash
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

python3 -m pip install --upgrade pip
python3 -m pip install .
```

After install:

```bash
wp-fingerprint --help
# or
python3 -m wp_core_fingerprint --help
```

> **Why not `pip install .` directly?**  
> On Debian, Ubuntu, Fedora, and other distros with PEP 668, system Python is "externally managed" and `pip install` without a venv fails with `externally-managed-environment`. Always use a venv (above) or pipx/Docker below.

### pipx (isolated global CLI)

```bash
pipx install git+https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
wp-fingerprint --url https://example.com/ --gentle
```

### Run without installing

```bash
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection
python3 -m wp_core_fingerprint --url https://example.com/ --gentle
```

### Docker

```bash
docker build -t wp-fingerprint .
docker run --rm wp-fingerprint --url https://example.com/ --gentle
```

### Windows

```powershell
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection
py -3.11 -m pip install .
wp-fingerprint --help
```

Use **`py -3.11`** (or your installed 3.10+) if the default `python` points to an unsupported or broken build.

---

## Quick start

**Basic scan** (homepage + core assets):

```bash
python3 -m wp_core_fingerprint --url https://example.com/blog/
```

**Production / WAF-friendly:**

```bash
python3 -m wp_core_fingerprint --url https://example.com/blog/ --gentle
```

**Modern WordPress only (faster, 6.9+ / 7.x tags):**

```bash
python3 -m wp_core_fingerprint --url https://example.com/blog/ --gentle --quick
```

**Full audit report:**

```bash
python3 -m wp_core_fingerprint \
  --url https://example.com/blog/ \
  --gentle \
  --quick \
  --crawl \
  --enumerate-plugins \
  --check-vulns \
  --output report.json \
  --markdown report.md \
  --html report.html \
  --sarif report.sarif
```

**Through Burp:**

```bash
python3 -m wp_core_fingerprint \
  --url https://target/ \
  --proxy http://127.0.0.1:8080 \
  --gentle
```

**JSON config file** (see `examples/scan-config.json`):

```bash
python3 -m wp_core_fingerprint --config my-scan.json
```

Second run on the same machine is much faster: reference data is cached under `~/.cache/wp-core-fingerprint/`.

While the scan runs, progress is printed step-by-step to **stderr** (reach target → core assets → tag matching → crawl → reports). Use `--quiet` to disable it for CI or scripting.

---

## How detection works

### Core (always on)

1. Fetch the homepage and up to **19 static core files** from `wp-includes/` (JS, CSS).
2. Compute **MD5** for each reachable file.
3. Detect the **era** (legacy / block / modern) to narrow candidate tags.
4. **Phase 1:** score anchor assets against filtered GitHub tags.
5. **Phase 2:** full weighted MD5 match on top candidates.
6. Pick the winner; **`unique_discriminators`** are files that match only the top tag among close patches.

Supplementary probes (when not in `--minimal-probes`): `version.php`, `readme.html`, `license.txt`, `wp-json/`, feeds, etc.

### Plugins & themes (`--crawl`)

1. BFS crawl from the start URL (respects `robots.txt` unless `--ignore-robots`).
2. Parse HTML for `wp-content/plugins/` and `wp-content/themes/` references.
3. Resolve versions from `readme.txt`, `style.css`, and plugin file headers.
4. Optional **`--enumerate-plugins`:** probe a built-in list of common plugin slugs even if not linked in HTML.

### Advisories (`--check-vulns`)

Looks up detected core/plugin/theme versions on WPVulnerability.net. Advisory hints only — not a full CVE database or exploit mapper.

---

## Output & exit codes

| Exit | Meaning |
|------|---------|
| `0` | Success; confidence meets `--min-confidence` |
| `1` | Runtime error |
| `2` | Confidence below `--min-confidence` |
| `3` | Target unreachable |

### Report formats

| Flag | Format | Use for |
|------|--------|---------|
| `--output` | JSON (schema 3.0) | Automation, evidence, full detail |
| `--markdown` | Markdown | Client / pentest reports |
| `--html` | HTML | Browser viewing |
| `--sarif` | SARIF 2.1 | GitHub Code Scanning, CI |

### Key JSON fields

| Field | Meaning |
|-------|---------|
| `detected_version` | Best core answer, e.g. `7.0.3` |
| `confidence` | `high` / `medium` / `low` / `insufficient` |
| `confidence_pct` | Weighted match percentage |
| `top_candidates` | Runner-up tags; small gap → note in report |
| `top_candidates[].unique_discriminators` | Patch-level proof assets |
| `asset_mismatches` | CDN/customization; does not always invalidate result |
| `plugins_detected` / `themes_detected` | With `--crawl`; includes `version_confidence` |
| `crawl_stats` | Pages crawled, plugins/themes discovered |
| `vulnerabilities` | With `--check-vulns` |
| `request_stats` | Retries, throttle, circuit breaker events |

**Markdown** output is ready to paste into a report. **SARIF** includes core unknown and advisory findings for CI.

---

## CLI reference

### Scan modes

| Flag | Description |
|------|-------------|
| `--url` | WordPress site base URL |
| `--config`, `-c` | JSON config file (CLI overrides config) |
| `--gentle` | Slow sequential target requests, more retries, relaxed SSL, minimal probes |
| `--quick` | Compare only recent 6.9.x / 7.x tags (faster) |
| `--minimal-probes` | Skip heavy supplementary paths (`debug.log`, `wp-json`, feed) |
| `--sequential` | Fetch target assets one-by-one |
| `--quiet` | Suppress step-by-step progress and final console summary |

### Crawl & extensions

| Flag | Description |
|------|-------------|
| `--crawl` | Crawl inner pages for plugin/theme inventory |
| `--crawl-max-pages` | Max pages to crawl (default: 50) |
| `--crawl-max-depth` | Max link depth (default: 3) |
| `--crawl-workers` | Parallel crawl workers (default: 2) |
| `--crawl-delay` | Seconds between crawl requests |
| `--enumerate-plugins` | Probe built-in common plugin wordlist |
| `--ignore-robots` | Ignore robots.txt (authorized testing only) |

### Reports & CI

| Flag | Description |
|------|-------------|
| `--output`, `-o` | JSON report path |
| `--markdown`, `-m` | Markdown report path |
| `--html` | HTML report path |
| `--sarif` | SARIF report path |
| `--check-vulns` | WPVulnerability.net advisory lookup |
| `--min-confidence` | Fail (exit 2) if below `low`/`medium`/`high` |

### HTTP & network

| Flag | Description |
|------|-------------|
| `--proxy` | HTTP(S) proxy, e.g. `http://127.0.0.1:8080` |
| `--cookie` | Cookie header for authenticated scans |
| `--header NAME:VALUE` | Extra header (repeatable) |
| `--user-agent` | Custom User-Agent |
| `--timeout` | HTTP timeout in seconds (default: 30) |
| `--relaxed-ssl` | Relaxed TLS cipher policy (helps some CDNs/WAFs) |
| `--target-delay` | Min seconds between target requests |
| `--github-delay` | Min seconds between GitHub requests |
| `--max-retries` | Retries for transient SSL/network errors |
| `--retry-backoff` | Exponential backoff base |
| `--max-requests` | Cap total HTTP requests (0 = unlimited) |

### Tuning & cache

| Flag | Description |
|------|-------------|
| `--workers` | Parallel asset fetch workers (use 1 with `--gentle`) |
| `--tag-workers` | Parallel tag scoring workers |
| `--min-major` | Minimum WP major version to compare |
| `--tag-limit` | Limit tags after era filter |
| `--phase1-limit` | Top N phase-1 tags to fully score |
| `--no-cache` | Disable SQLite reference cache |

Full list: `python3 -m wp_core_fingerprint --help`

---

## Example config

`examples/scan-config.json`:

```json
{
  "url": "https://example.com/blog/",
  "gentle": true,
  "crawl": true,
  "crawl_max_pages": 60,
  "enumerate_plugins": true,
  "check_vulns": true,
  "min_confidence": "medium",
  "output": "report.json",
  "markdown": "report.md",
  "html": "report.html"
}
```

Config files saved from Windows editors may include a UTF-8 BOM; the loader handles that automatically.

---

## Limits (honest)

- Targets that are not WordPress (or block all `wp-includes/` assets) return `insufficient` confidence — that is expected.
- Admin-only plugins with no public HTML footprint will not appear.
- Blocked `readme.txt` / `style.css` means plugin/theme version may stay `unknown`.
- Theme slugs parsed from inline CSS class names may appear as false positives; check `version_confidence`.
- Not user enumeration, not login testing, not a replacement for WPScan's CVE database.
- **Authorized testing only.** Prefer `--gentle` on systems you do not own.

---

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m unittest tests.test_core -v
```

---

## License

MIT. See [LICENSE](LICENSE).

Maintained by [Erfanmghs](https://github.com/Erfanmghs).

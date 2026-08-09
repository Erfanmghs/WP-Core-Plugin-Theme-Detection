# WordPress Core, Plugin & Theme Detection

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Remote fingerprinting for WordPress **core** (down to the patch) and, with `--crawl`, **plugins and themes**. Built for hardened sites where generator meta, `readme.html`, and `version.php` no longer leak the version.

Passive only — public HTTP GET requests. No login, no Ruby, no API token for core detection.

| | |
|---|---|
| **PyPI-style name** | `wp-core-fingerprint` |
| **CLI command** | `wp-fingerprint` |
| **Python module** | `python3 -m wp_core_fingerprint` |
| **Repository** | https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection |

---

## Table of contents

- [Features](#features)
- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Installation](#installation)
- [First run (step by step)](#first-run-step-by-step)
- [Usage examples](#usage-examples)
- [While the scan runs (progress output)](#while-the-scan-runs-progress-output)
- [How long does it take?](#how-long-does-it-take)
- [Reading the output](#reading-the-output)
- [How detection works](#how-detection-works)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)
- [Development](#development)
- [License](#license)

---

## Features

| Area | What you get |
|------|----------------|
| **Core version** | MD5 fingerprint of up to 19 public `wp-includes/` assets vs **860+ official GitHub release tags** (WP 1.5 → 7.x) |
| **Patch-level evidence** | Weighted scoring, era detection, `unique_discriminators` separating close patches (e.g. 7.0.2 vs 7.0.3) |
| **Live progress** | Step-by-step status on stderr so long scans do not look frozen |
| **Plugin & theme inventory** | `--crawl` BFS over inner pages; version resolution via `readme.txt`, `style.css`, plugin headers |
| **Plugin enumeration** | `--enumerate-plugins` probes a built-in wordlist of common plugin slugs |
| **Advisory hints** | `--check-vulns` queries [WPVulnerability.net](https://www.wpvulnerability.net/) (no API key) |
| **Reports** | JSON (schema 3.0), Markdown, HTML, SARIF (GitHub Code Scanning) |
| **Production-safe pacing** | `--gentle` slow sequential requests, retries, circuit breaker, relaxed SSL |
| **CI integration** | `--min-confidence` exit code 2; `--sarif` for pipelines; `--quiet` for scripts |
| **Config files** | JSON config (`examples/scan-config.json`); CLI overrides config |
| **Burp / proxy** | `--proxy`, `--cookie`, repeatable `--header` |
| **Caching** | SQLite cache at `~/.cache/wp-core-fingerprint/` |
| **Docker** | Container with `wp-fingerprint` entrypoint |

---

## Why this exists

On a pentest or audit you often hit WordPress that has:

- no `<meta name="generator">`
- `readme.html` returning 404
- `wp-includes/version.php` returning an empty body (PHP executes server-side)

You still need the exact core version before CVE mapping means anything.

This tool compares public core file hashes against every stable release on GitHub. When several assets match one tag and one file only matches that tag among the top candidates, you get patch-level confidence even on hardened installs.

**WPScan** ([wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)) is excellent for broad scanning but needs an API token and uses heuristics for core. Use both when you can: this tool for **exact core + evidence**, WPScan for **enumeration and CVE mapping**.

---

## Requirements

- **Python 3.10+** (stdlib only at runtime — no pip dependencies required to scan)
- Outbound HTTPS to the **target site** and to **`raw.githubusercontent.com`** (reference files)
- **Written authorization** for the target

> **Linux note:** many distros ship `python3` but not `python`. Always use **`python3`** and **`python3 -m pip`** below — not bare `python` or `pip`.

> **Debian / Ubuntu note:** system Python is [externally managed (PEP 668)](https://peps.python.org/pep-0668/). Use a **virtual environment** or **pipx** — do not `pip install` into system Python unless you know what you are doing.

---

## Installation

Pick **one** method.

### A) Linux / macOS — virtual environment (recommended)

```bash
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install .
```

Verify:

```bash
wp-fingerprint --help
# should print usage; exit code 0
```

Stay inside the venv (`source .venv/bin/activate`) whenever you run scans in this terminal session.

### B) pipx — global isolated CLI

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install git+https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
wp-fingerprint --help
```

### C) Run without installing

```bash
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection
python3 -m wp_core_fingerprint --help
```

### D) Docker

```bash
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection
docker build -t wp-fingerprint .
docker run --rm wp-fingerprint --url https://example.com/ --gentle
```

### E) Windows

```powershell
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3.11 -m pip install .
wp-fingerprint --help
```

Use **`py -3.10`** or newer if `python` is missing or points to an old runtime.

---

## First run (step by step)

Follow this exactly on **Linux** after installation method **A**:

```bash
# 1. Clone (skip if already done)
git clone https://github.com/Erfanmghs/WP-Core-Plugin-Theme-Detection.git
cd WP-Core-Plugin-Theme-Detection

# 2. Create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install (inside venv)
python3 -m pip install --upgrade pip
python3 -m pip install .

# 4. Confirm CLI works
wp-fingerprint --help

# 5. Run a gentle scan (replace URL with your authorized target)
wp-fingerprint \
  --url https://example.com/blog/ \
  --gentle \
  --quick \
  --output report.json \
  --markdown report.md

# 6. Check results
cat report.json | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['detected_version'], r['confidence'])"
```

You should see **progress lines on stderr** during step 5, then a **summary block**, then report file paths. If stderr stays silent for more than a minute in `--gentle` mode, that is normal — requests are intentionally throttled.

---

## Usage examples

All examples assume the venv is active (`source .venv/bin/activate`) or you use `python3 -m wp_core_fingerprint` from the repo directory.

**Basic scan** (homepage + core assets):

```bash
wp-fingerprint --url https://example.com/blog/
```

**Production / WAF-friendly** (recommended for real targets):

```bash
wp-fingerprint --url https://example.com/blog/ --gentle
```

**Modern WordPress only** (faster — 6.9+ / 7.x tags):

```bash
wp-fingerprint --url https://example.com/blog/ --gentle --quick
```

**Full audit** (core + crawl + plugins + advisories + all report formats):

```bash
wp-fingerprint \
  --url https://example.com/blog/ \
  --gentle \
  --quick \
  --crawl \
  --crawl-max-pages 30 \
  --enumerate-plugins \
  --check-vulns \
  --output report.json \
  --markdown report.md \
  --html report.html \
  --sarif report.sarif
```

**Through Burp:**

```bash
wp-fingerprint \
  --url https://target/ \
  --proxy http://127.0.0.1:8080 \
  --gentle
```

**JSON config file** (copy `examples/scan-config.json`, edit `url`):

```bash
wp-fingerprint --config my-scan.json
```

**CI: fail if confidence too low:**

```bash
wp-fingerprint --url https://staging/ --min-confidence medium
echo $?   # 2 = below threshold
```

**Scripting: no progress noise:**

```bash
wp-fingerprint --url https://example.com/ --gentle --quiet --output report.json
```

Second run on the same machine is faster — GitHub reference data is cached under `~/.cache/wp-core-fingerprint/`.

---

## While the scan runs (progress output)

By default the tool prints **step-by-step progress to stderr**. This is intentional — gentle scans can take minutes and should not look hung.

Example:

```
WordPress fingerprint scan
  Target:  https://example.com/blog/
  Profile: gentle
      gentle mode: slow pacing — a full scan may take several minutes

==> Reach target
  [1] Fetching homepage ...
      done: homepage HTTP 200, 98,432 bytes

==> Core fingerprint
  [2] Downloading wp-includes assets ...
      core asset 1/19: underscore.min.js ...
      ...
      done: 18/19 core assets fingerprinted

==> Version matching
  [3] Loading GitHub release tag list ...
      done: 860 tags in cache/API
  [4] Phase 1: anchor scoring ...
      done: top anchor match: 7.0.3 (8 assets)
  [5] Phase 2: full MD5 match ...
      done: best match: 7.0.3 (18/18, 100.0%)

==> Writing reports
      JSON -> report.json

============================================================
Detected:   7.0.3
Confidence: high (100.0%)
...
```

| Stream | Content |
|--------|---------|
| **stderr** | Live progress (phases, assets, crawl pages) |
| **stdout** | Final summary + report paths |
| **`--quiet`** | Suppresses both progress and summary |

---

## How long does it take?

| Profile | Typical runtime | Notes |
|---------|-----------------|-------|
| Normal, core only | 30 s – 2 min | Parallel asset fetch |
| `--gentle --quick`, core only | 1 – 7 min | Throttled; first run fetches GitHub refs |
| `--gentle --crawl --enumerate-plugins` | 10 – 90+ min | Many pages + wordlist probes; `--crawl-max-pages` limits scope |
| Repeat scan (cached) | Much faster | SQLite cache warm |

Use `--quick` when you know the site is on WordPress 6.9+ or 7.x. Use `--crawl-max-pages 10` for a quick plugin inventory smoke test.

---

## Reading the output

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success; confidence meets `--min-confidence` |
| `1` | Runtime error |
| `2` | Confidence below `--min-confidence` |
| `3` | Target unreachable |

### Report formats

| Flag | Format | Use for |
|------|--------|---------|
| `--output` | JSON (schema 3.0) | Automation, evidence |
| `--markdown` | Markdown | Client / pentest reports |
| `--html` | HTML | Browser viewing |
| `--sarif` | SARIF 2.1 | GitHub Code Scanning, CI |

### Key JSON fields

| Field | Meaning |
|-------|---------|
| `detected_version` | Best core answer, e.g. `7.0.3` |
| `confidence` | `high` / `medium` / `low` / `insufficient` |
| `confidence_pct` | Weighted match percentage |
| `top_candidates` | Runner-up tags |
| `top_candidates[].unique_discriminators` | Patch-level proof assets |
| `asset_mismatches` | CDN/customization deltas |
| `plugins_detected` / `themes_detected` | With `--crawl` |
| `crawl_stats` | Pages crawled, inventory counts |
| `vulnerabilities` | With `--check-vulns` |
| `request_stats` | Retries, throttle, circuit breaker |

---

## How detection works

### Core (always on)

1. Fetch homepage and up to **19 static core files** from `wp-includes/`.
2. Compute **MD5** for each reachable file.
3. Detect **era** (legacy / block / modern) to narrow candidate tags.
4. **Phase 1:** anchor asset scoring across filtered GitHub tags.
5. **Phase 2:** full weighted MD5 match on finalists.
6. **`unique_discriminators`** prove patch level when tags are close.

### Plugins & themes (`--crawl`)

1. BFS crawl from start URL (respects `robots.txt` unless `--ignore-robots`).
2. Parse HTML for plugin/theme references.
3. Resolve versions from `readme.txt`, `style.css`, plugin headers.
4. **`--enumerate-plugins`:** probe built-in common slug wordlist.

### Advisories (`--check-vulns`)

Looks up detected versions on WPVulnerability.net. Hints only — not a full CVE database.

---

## CLI reference

### Scan modes

| Flag | Description |
|------|-------------|
| `--url` | WordPress site base URL |
| `--config`, `-c` | JSON config file (CLI overrides config) |
| `--gentle` | Slow sequential requests, retries, relaxed SSL, minimal probes |
| `--quick` | Recent 6.9.x / 7.x tags only (faster) |
| `--minimal-probes` | Skip heavy supplementary paths |
| `--sequential` | Fetch target assets one-by-one |
| `--quiet` | No progress or summary (for CI/scripts) |

### Crawl & extensions

| Flag | Default | Description |
|------|---------|-------------|
| `--crawl` | off | Crawl inner pages for plugin/theme inventory |
| `--crawl-max-pages` | 50 | Max pages to fetch |
| `--crawl-max-depth` | 3 | Max link depth |
| `--crawl-workers` | 2 | Parallel crawl workers |
| `--crawl-delay` | auto | Seconds between crawl requests |
| `--enumerate-plugins` | off | Probe common plugin wordlist |
| `--ignore-robots` | off | Skip robots.txt (authorized only) |

### Reports & CI

| Flag | Description |
|------|-------------|
| `--output`, `-o` | JSON report path |
| `--markdown`, `-m` | Markdown report path |
| `--html` | HTML report path |
| `--sarif` | SARIF report path |
| `--check-vulns` | WPVulnerability.net lookup |
| `--min-confidence` | Exit 2 if below threshold |

### HTTP & tuning

| Flag | Description |
|------|-------------|
| `--proxy` | HTTP(S) proxy URL |
| `--cookie` | Cookie header value |
| `--header NAME:VALUE` | Extra header (repeatable) |
| `--user-agent` | Custom User-Agent |
| `--timeout` | HTTP timeout (seconds) |
| `--relaxed-ssl` | Relaxed TLS ciphers |
| `--target-delay` | Min delay between target requests |
| `--github-delay` | Min delay between GitHub requests |
| `--max-retries` | Transient error retries |
| `--workers` | Parallel asset workers (1 with `--gentle`) |
| `--tag-workers` | Parallel tag scoring workers |
| `--no-cache` | Disable SQLite cache |
| `--max-requests` | Cap total HTTP requests (0 = unlimited) |

Full list: `wp-fingerprint --help`

---

## Example config

`examples/scan-config.json`:

```json
{
  "url": "https://example.com/blog/",
  "gentle": true,
  "quick": true,
  "crawl": true,
  "crawl_max_pages": 30,
  "enumerate_plugins": true,
  "check_vulns": true,
  "min_confidence": "medium",
  "output": "report.json",
  "markdown": "report.md",
  "html": "report.html",
  "sarif": "report.sarif"
}
```

Run:

```bash
wp-fingerprint --config examples/scan-config.json
```

Config files from Windows editors may include a UTF-8 BOM — supported automatically.

---

## Troubleshooting

### `error: externally-managed-environment` (Debian / Ubuntu / Kali)

You tried `pip install .` on **system Python**. Fix:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

Do **not** use `--break-system-packages` unless you fully understand the risk.

### `python: command not found` but `python3` works

Use `python3` and `python3 -m wp_core_fingerprint` everywhere, or activate a venv and use `wp-fingerprint`.

### Nothing appears for a long time

- With **`--gentle`**, silence between lines is normal (delays are intentional).
- Progress goes to **stderr** — make sure you are not redirecting stderr away.
- Use **`--quiet`** only in scripts; omit it for interactive use.

### `ERROR: Cannot reach target` / SSL errors

- Confirm the URL in a browser or `curl -I https://target/`.
- Try **`--gentle`** (enables relaxed SSL and retries).
- Some targets rate-limit after many requests — wait and retry, or reduce `--crawl-max-pages`.

### `Detected: unknown` / `insufficient` confidence

- Target may not be WordPress, or all `wp-includes/` assets are blocked.
- Try the site root or the path where `/wp-content/` URLs appear in HTML.
- Non-WP apps under a subdirectory (e.g. `/b2b/`) will correctly return insufficient.

### `wp-fingerprint: command not found` after install

- Venv not activated: `source .venv/bin/activate`
- Or run: `python3 -m wp_core_fingerprint ...`
- Or reinstall: `python3 -m pip install . --force-reinstall`

### Reports empty or missing plugins

- Add **`--crawl`** and optionally **`--enumerate-plugins`**.
- Increase **`--crawl-max-pages`**.
- Check `version_confidence` — blocked `readme.txt` yields `unknown`.

---

## Limits

- Non-WordPress targets or fully blocked assets → `insufficient` (expected).
- Admin-only plugins with no public footprint are invisible.
- Theme slugs from inline CSS may include false positives — trust `version_confidence`.
- Not user enumeration, not login testing, not a WPScan replacement.
- **Authorized testing only.** Prefer `--gentle` on production.

---

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m unittest tests.test_core -v
```

CI runs on Python 3.10, 3.11, and 3.12 via GitHub Actions.

---

## License

MIT — see [LICENSE](LICENSE).

Maintained by [Erfanmghs](https://github.com/Erfanmghs).

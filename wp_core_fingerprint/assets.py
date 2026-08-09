"""WordPress core asset catalog — multi-era fingerprint definitions."""
from __future__ import annotations

from typing import Any

# Each asset may specify:
#   live_path: fetched from target (required)
#   github_paths: tried in order when comparing to release tags
#   weight: scoring weight
#   category: report grouping
#   min_wp: (major, minor) earliest tag expected to contain file
#   max_wp: (major, minor) exclusive upper bound, or None

ASSET_CATALOG: list[dict[str, Any]] = [
    # --- Universal classic (3.8+) ---
    {
        "name": "underscore.min.js",
        "live_path": "wp-includes/js/underscore.min.js",
        "github_paths": ["wp-includes/js/underscore.min.js"],
        "weight": 2.5,
        "category": "js-classic",
        "min_wp": (3, 8),
        "max_wp": None,
    },
    {
        "name": "backbone.min.js",
        "live_path": "wp-includes/js/backbone.min.js",
        "github_paths": ["wp-includes/js/backbone.min.js"],
        "weight": 2.5,
        "category": "js-classic",
        "min_wp": (3, 8),
        "max_wp": None,
    },
    {
        "name": "dashicons.min.css",
        "live_path": "wp-includes/css/dashicons.min.css",
        "github_paths": ["wp-includes/css/dashicons.min.css"],
        "weight": 2.0,
        "category": "css-classic",
        "min_wp": (3, 8),
        "max_wp": None,
    },
    {
        "name": "wp-util.min.js",
        "live_path": "wp-includes/js/wp-util.min.js",
        "github_paths": ["wp-includes/js/wp-util.min.js"],
        "weight": 2.0,
        "category": "js-classic",
        "min_wp": (3, 8),
        "max_wp": None,
    },
    # --- jQuery (bundled; path/min naming varies by release) ---
    {
        "name": "jquery.min.js",
        "live_path": "wp-includes/js/jquery/jquery.min.js",
        "github_paths": [
            "wp-includes/js/jquery/jquery.min.js",
            "wp-includes/js/jquery/jquery.js",
        ],
        "weight": 1.5,
        "category": "jquery",
        "min_wp": (3, 0),
        "max_wp": None,
    },
    {
        "name": "jquery-migrate.min.js",
        "live_path": "wp-includes/js/jquery/jquery-migrate.min.js",
        "github_paths": [
            "wp-includes/js/jquery/jquery-migrate.min.js",
            "wp-includes/js/jquery/jquery-migrate.js",
        ],
        "weight": 1.0,
        "category": "jquery",
        "min_wp": (3, 6),
        "max_wp": None,
    },
    # --- Emoji (4.2+ release bundle; older sites use wp-emoji.min.js) ---
    {
        "name": "wp-emoji-release.min.js",
        "live_path": "wp-includes/js/wp-emoji-release.min.js",
        "github_paths": ["wp-includes/js/wp-emoji-release.min.js"],
        "weight": 2.5,
        "category": "emoji",
        "min_wp": (4, 2),
        "max_wp": None,
    },
    {
        "name": "wp-emoji.min.js",
        "live_path": "wp-includes/js/wp-emoji.min.js",
        "github_paths": ["wp-includes/js/wp-emoji.min.js"],
        "weight": 2.0,
        "category": "emoji",
        "min_wp": (4, 2),
        "max_wp": (5, 9),
    },
    {
        "name": "wp-emoji-loader.min.js",
        "live_path": "wp-includes/js/wp-emoji-loader.min.js",
        "github_paths": ["wp-includes/js/wp-emoji-loader.min.js"],
        "weight": 3.0,
        "category": "emoji",
        "min_wp": (4, 2),
        "max_wp": None,
    },
    # --- Block editor / Gutenberg dist (5.0+) ---
    {
        "name": "hooks.min.js",
        "live_path": "wp-includes/js/dist/hooks.min.js",
        "github_paths": ["wp-includes/js/dist/hooks.min.js"],
        "weight": 2.5,
        "category": "js-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "i18n.min.js",
        "live_path": "wp-includes/js/dist/i18n.min.js",
        "github_paths": ["wp-includes/js/dist/i18n.min.js"],
        "weight": 2.5,
        "category": "js-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "dom-ready.min.js",
        "live_path": "wp-includes/js/dist/dom-ready.min.js",
        "github_paths": ["wp-includes/js/dist/dom-ready.min.js"],
        "weight": 1.5,
        "category": "js-dist",
        "min_wp": (5, 2),
        "max_wp": None,
    },
    {
        "name": "a11y.min.js",
        "live_path": "wp-includes/js/dist/a11y.min.js",
        "github_paths": ["wp-includes/js/dist/a11y.min.js"],
        "weight": 1.5,
        "category": "js-dist",
        "min_wp": (5, 2),
        "max_wp": None,
    },
    {
        "name": "api-fetch.min.js",
        "live_path": "wp-includes/js/dist/api-fetch.min.js",
        "github_paths": ["wp-includes/js/dist/api-fetch.min.js"],
        "weight": 2.0,
        "category": "js-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "url.min.js",
        "live_path": "wp-includes/js/dist/url.min.js",
        "github_paths": ["wp-includes/js/dist/url.min.js"],
        "weight": 1.5,
        "category": "js-dist",
        "min_wp": (5, 3),
        "max_wp": None,
    },
    {
        "name": "components.min.js",
        "live_path": "wp-includes/js/dist/components.min.js",
        "github_paths": ["wp-includes/js/dist/components.min.js"],
        "weight": 3.0,
        "category": "js-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "block-library-style.min.css",
        "live_path": "wp-includes/css/dist/block-library/style.min.css",
        "github_paths": ["wp-includes/css/dist/block-library/style.min.css"],
        "weight": 2.5,
        "category": "css-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "block-editor-style.min.css",
        "live_path": "wp-includes/css/dist/block-editor/style.min.css",
        "github_paths": ["wp-includes/css/dist/block-editor/style.min.css"],
        "weight": 2.5,
        "category": "css-dist",
        "min_wp": (5, 0),
        "max_wp": None,
    },
    {
        "name": "theme.min.css",
        "live_path": "wp-includes/css/dist/block-library/theme.min.css",
        "github_paths": ["wp-includes/css/dist/block-library/theme.min.css"],
        "weight": 1.5,
        "category": "css-dist",
        "min_wp": (5, 7),
        "max_wp": None,
    },
]

# Fast subset for phase-1 candidate filtering (exist across most releases)
ANCHOR_ASSET_NAMES = [
    "underscore.min.js",
    "backbone.min.js",
    "dashicons.min.css",
    "wp-util.min.js",
    "hooks.min.js",
    "jquery.min.js",
    "wp-emoji-release.min.js",
]

SUPPORTED_VERSION_RANGE = "WordPress 1.5 through latest (all GitHub release tags)"

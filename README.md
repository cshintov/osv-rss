# osv-rss

**Atom feeds of new & updated open-source vulnerabilities, per ecosystem — because [osv.dev](https://osv.dev) doesn't ship one.**

osv.dev has no official RSS/Atom feed (requests [#4103](https://github.com/google/osv.dev/issues/4103) and [#3555](https://github.com/google/osv.dev/issues/3555) were both closed *not planned*), and its API is lookup-only — there's no "what's new" endpoint. This repo closes that gap: a tiny GitHub Action reads the public [OSV.dev data exports](https://google.github.io/osv.dev/data/) every 6 hours and publishes one Atom feed per ecosystem to GitHub Pages.

## Feeds

Once Pages is live, subscribe to whichever match your stack:

| Ecosystem | Feed |
|-----------|------|
| npm | `https://cshintov.github.io/osv-rss/npm.xml` |
| PyPI (Python) | `https://cshintov.github.io/osv-rss/pypi.xml` |
| Go | `https://cshintov.github.io/osv-rss/go.xml` |
| Maven (Java) | `https://cshintov.github.io/osv-rss/maven.xml` |
| crates.io (Rust) | `https://cshintov.github.io/osv-rss/crates.xml` |
| RubyGems | `https://cshintov.github.io/osv-rss/rubygems.xml` |
| NuGet (.NET) | `https://cshintov.github.io/osv-rss/nuget.xml` |

Index page: `https://cshintov.github.io/osv-rss/`

## How it works

```
modified_id.csv (sorted newest-first)  ──►  take items within the time window
        │                                          │
        │ (per ecosystem, public GCS bucket)       ▼
        └───────────────────────────────►  hydrate each record JSON from the bucket
                                                   │
                                                   ▼
                                          render Atom 1.0 ──► GitHub Pages
```

- **Discovery** uses each ecosystem's `modified_id.csv` (`<modified-timestamp>,<ID>`, sorted newest-first), so we only read the top slice — never the 200 MB `all.zip`.
- **Hydration** reads `…/<ecosystem>/<ID>.json` straight from the bucket (the intended bulk path), not the rate-limited query API.
- Entries are tagged `[NEW]` (published within the window) or `[UPDATED]`, and carry summary, aliases (CVE), severity, affected packages + fixed versions, details, and source references.
- Quiet ecosystems still show their most-recent ~15 items so feeds are never empty.

## Run it yourself

```sh
python3 generate.py          # writes feeds/*.xml + feeds/index.html  (stdlib only, no deps)
```

Tunables (env vars): `OSV_RSS_WINDOW_HOURS` (default 48), `OSV_RSS_MIN_ITEMS` (15),
`OSV_RSS_MAX_ITEMS` (150), `OSV_RSS_BASE_URL`, `OSV_RSS_OUT`.

Deployment is `.github/workflows/build.yml`: runs on a 6-hourly cron + manual dispatch,
generates `feeds/`, and deploys via `actions/deploy-pages`. No commit-back, no stored state.

## Data & license

Vulnerability data comes from **[OSV.dev](https://osv.dev)** and its upstream sources
(notably the **GitHub Advisory Database**), licensed **[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)**.
Every feed entry links back to `osv.dev/vulnerability/<ID>` and preserves the original
references. This is an **independent, unofficial** mirror — not affiliated with or endorsed by OSV.dev or Google.

The code in this repo is MIT-licensed.

#!/usr/bin/env python3
"""
osv-rss — generate Atom feeds of new/updated open-source vulnerabilities from
the public OSV.dev data exports.

WHY this shape: the OSV API has no "what's new" endpoint (lookup-only). Discovery
comes from the GCS export bucket's per-ecosystem `modified_id.csv`, which is
`<modified-timestamp>,<ID>` sorted newest-first. We read only the top slice
within a time window, hydrate each record's JSON straight from the bucket (the
intended bulk path — not the query API), and render one Atom feed per ecosystem.

Data: OSV.dev and its upstream sources (e.g. GitHub Advisory Database). Licensed
CC-BY-4.0 — every entry links back to osv.dev and preserves source references.

Zero third-party dependencies (stdlib only).
"""

import concurrent.futures as cf
import html
import json
import os
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape as xml_escape

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
# Public Pages URL; override in CI via env if the repo name/owner differs.
BASE_URL = os.environ.get("OSV_RSS_BASE_URL", "https://cshintov.github.io/osv-rss").rstrip("/")
OUT_DIR = os.environ.get("OSV_RSS_OUT", "feeds")

# Hours of history each feed covers. With a 6h cron this overlaps comfortably.
WINDOW_HOURS = int(os.environ.get("OSV_RSS_WINDOW_HOURS", "48"))
# Hard cap on records hydrated per ecosystem per run (bounds runtime / politeness).
MAX_ITEMS = int(os.environ.get("OSV_RSS_MAX_ITEMS", "150"))
# Floor: always carry at least this many most-recent items, even if older than the
# window — so quiet ecosystems (Go, crates.io…) aren't empty on first subscribe.
MIN_ITEMS = int(os.environ.get("OSV_RSS_MIN_ITEMS", "15"))

# Ecosystem dir name in the bucket -> (slug for filename, human label).
ECOSYSTEMS = {
    "npm":       ("npm", "npm"),
    "PyPI":      ("pypi", "PyPI (Python)"),
    "Go":        ("go", "Go"),
    "Maven":     ("maven", "Maven (Java)"),
    "crates.io": ("crates", "crates.io (Rust)"),
    "RubyGems":  ("rubygems", "RubyGems"),
    "NuGet":     ("nuget", "NuGet (.NET)"),
}

UA = {"User-Agent": "osv-rss/1.0 (+https://github.com/cshintov/osv-rss)"}
NOW = datetime.now(timezone.utc)
CUTOFF = NOW - timedelta(hours=WINDOW_HOURS)


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_ts(s: str) -> datetime:
    """Parse an OSV/RFC3339 timestamp into an aware UTC datetime."""
    if not s:
        return NOW
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Python's fromisoformat chokes on >6 fractional digits; trim them.
    if "." in s:
        head, _, tail = s.partition(".")
        digits = ""
        for ch in tail:
            if ch.isdigit():
                digits += ch
            else:
                tail_rest = tail[len(digits):]
                break
        else:
            tail_rest = ""
        s = f"{head}.{digits[:6]}{tail_rest}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return NOW
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def recent_ids(eco: str) -> list[str]:
    """Read modified_id.csv (sorted newest-first) and return IDs modified within
    the window (capped at MAX_ITEMS), or — if fewer than MIN_ITEMS fall in the
    window — the MIN_ITEMS most-recent IDs so the feed is never empty."""
    enc = urllib.parse.quote(eco)
    raw = _get(f"{BUCKET}/{enc}/modified_id.csv").decode("utf-8", "replace")
    rows: list[tuple[datetime, str]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        ts_str, _, vid = line.partition(",")
        if not vid:
            continue
        rows.append((parse_ts(ts_str), vid.strip()))
        if len(rows) >= MAX_ITEMS:
            break  # file is sorted desc — we have the most-recent slice
    in_window = [vid for ts, vid in rows if ts >= CUTOFF]
    if len(in_window) >= MIN_ITEMS:
        return in_window
    return [vid for _, vid in rows[:MIN_ITEMS]]  # floor: most-recent N


def hydrate(eco: str, vid: str) -> dict | None:
    enc = urllib.parse.quote(eco)
    try:
        return json.loads(_get(f"{BUCKET}/{enc}/{vid}.json"))
    except Exception as e:  # noqa: BLE001 — a single bad record shouldn't kill the run
        print(f"  warn: hydrate {eco}/{vid} failed: {e}", file=sys.stderr)
        return None


def osv_url(vid: str) -> str:
    return f"https://osv.dev/vulnerability/{urllib.parse.quote(vid)}"


def entry_html(rec: dict) -> str:
    """Compact HTML body for an Atom entry."""
    parts: list[str] = []
    if rec.get("summary"):
        parts.append(f"<p><strong>{html.escape(rec['summary'])}</strong></p>")
    if rec.get("aliases"):
        parts.append("<p>Aliases: " + ", ".join(html.escape(a) for a in rec["aliases"]) + "</p>")
    sev = rec.get("severity") or []
    if sev:
        bits = [html.escape(f"{s.get('type','')}: {s.get('score','')}") for s in sev]
        parts.append("<p>Severity: " + " · ".join(bits) + "</p>")
    affected = rec.get("affected") or []
    if affected:
        rows = []
        for a in affected[:12]:
            pkg = a.get("package", {})
            name = pkg.get("name", "?")
            fixed = []
            for rng in a.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])
            fx = f" — fixed in {html.escape(', '.join(fixed))}" if fixed else ""
            rows.append(f"<li><code>{html.escape(str(name))}</code>{fx}</li>")
        parts.append("<p>Affected:</p><ul>" + "".join(rows) + "</ul>")
    if rec.get("details"):
        d = rec["details"]
        d = d[:800] + ("…" if len(d) > 800 else "")
        parts.append(f"<p>{html.escape(d)}</p>")
    refs = rec.get("references") or []
    if refs:
        links = []
        for r in refs[:8]:
            u = r.get("url", "")
            if u:
                links.append(f'<li><a href="{html.escape(u)}">{html.escape(u)}</a></li>')
        if links:
            parts.append("<p>References:</p><ul>" + "".join(links) + "</ul>")
    parts.append(f'<p><a href="{osv_url(rec["id"])}">View on OSV.dev →</a></p>')
    return "".join(parts)


def build_feed(eco: str, slug: str, label: str, records: list[dict]) -> str:
    self_url = f"{BASE_URL}/{slug}.xml"
    feed_updated = max((parse_ts(r.get("modified", "")) for r in records), default=NOW)
    out = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        f"  <title>OSV — new &amp; updated vulnerabilities: {xml_escape(label)}</title>",
        f"  <subtitle>Open-source vulns affecting {xml_escape(label)} packages, last {WINDOW_HOURS}h. Source: OSV.dev (CC-BY-4.0).</subtitle>",
        f"  <id>tag:cshintov.github.io,2026:osv-rss:{slug}</id>",
        f"  <updated>{feed_updated.strftime('%Y-%m-%dT%H:%M:%SZ')}</updated>",
        f'  <link rel="self" href="{xml_escape(self_url)}"/>',
        '  <link rel="alternate" href="https://osv.dev/"/>',
        "  <author><name>osv-rss (data from OSV.dev)</name></author>",
        "  <rights>Vulnerability data from OSV.dev and upstream sources (e.g. GitHub Advisory Database), licensed CC-BY-4.0.</rights>",
        f"  <generator uri=\"https://github.com/cshintov/osv-rss\">osv-rss</generator>",
    ]
    for rec in records:
        vid = rec.get("id", "")
        if not vid:
            continue
        published = parse_ts(rec.get("published", rec.get("modified", "")))
        modified = parse_ts(rec.get("modified", ""))
        is_new = published >= CUTOFF
        tag = "NEW" if is_new else "UPDATED"
        summary = rec.get("summary") or (rec.get("details", "")[:120] or vid)
        title = f"[{tag}] {vid}: {summary}"
        out += [
            "  <entry>",
            f"    <title>{xml_escape(title)}</title>",
            f"    <id>{xml_escape(osv_url(vid))}</id>",
            f'    <link rel="alternate" href="{xml_escape(osv_url(vid))}"/>',
            f"    <published>{published.strftime('%Y-%m-%dT%H:%M:%SZ')}</published>",
            f"    <updated>{modified.strftime('%Y-%m-%dT%H:%M:%SZ')}</updated>",
            f'    <category term="{xml_escape(eco)}"/>',
        ]
        for alias in rec.get("aliases", []):
            out.append(f'    <category term="{xml_escape(alias)}"/>')
        out.append(f'    <content type="html">{xml_escape(entry_html(rec))}</content>')
        out.append("  </entry>")
    out.append("</feed>")
    return "\n".join(out)


def build_index(results: dict[str, dict]) -> str:
    rows = []
    for eco, info in results.items():
        slug, label, n = info["slug"], info["label"], info["count"]
        rows.append(
            f'<tr><td>{html.escape(label)}</td>'
            f'<td><a href="{slug}.xml">{slug}.xml</a></td>'
            f"<td>{n}</td></tr>"
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>osv-rss — OSV vulnerability feeds</title>
<style>
 body{{font:16px/1.6 -apple-system,system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 20px;color:#111}}
 h1{{font-size:28px;margin:0 0 4px}} .sub{{color:#666;margin:0 0 28px}}
 table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #eee}}
 th{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#888}}
 code{{background:#f4f4f4;padding:1px 5px;border-radius:3px}} a{{color:#0a58ca}}
 footer{{margin-top:32px;font-size:13px;color:#888}}
</style></head><body>
<h1>osv-rss</h1>
<p class="sub">Atom feeds of new &amp; updated open-source vulnerabilities, last {WINDOW_HOURS}h, per ecosystem.
Subscribe to the ones matching your stack.</p>
<table><thead><tr><th>Ecosystem</th><th>Feed</th><th>Items</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<footer>
<p>Updated {NOW.strftime('%Y-%m-%d %H:%M UTC')}. Built by
<a href="https://github.com/cshintov/osv-rss">osv-rss</a> from the
<a href="https://google.github.io/osv.dev/data/">OSV.dev data exports</a>.</p>
<p>Vulnerability data © OSV.dev and upstream sources (e.g. GitHub Advisory Database),
licensed <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>.
osv.dev does not provide an official RSS feed; this is an independent mirror.</p>
</footer></body></html>"""


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    results: dict[str, dict] = {}
    total = 0
    for eco, (slug, label) in ECOSYSTEMS.items():
        try:
            ids = recent_ids(eco)
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: {eco} modified_id.csv failed: {e}", file=sys.stderr)
            ids = []
        records: list[dict] = []
        if ids:
            with cf.ThreadPoolExecutor(max_workers=8) as ex:
                for rec in ex.map(lambda i: hydrate(eco, i), ids):
                    if rec and not rec.get("withdrawn"):
                        records.append(rec)
        # newest modified first
        records.sort(key=lambda r: parse_ts(r.get("modified", "")), reverse=True)
        xml = build_feed(eco, slug, label, records)
        path = os.path.join(OUT_DIR, f"{slug}.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml)
        results[eco] = {"slug": slug, "label": label, "count": len(records)}
        total += len(records)
        print(f"  {label:18s} -> {slug}.xml  ({len(records)} items)")
    with open(os.path.join(OUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(build_index(results))
    print(f"Done: {total} items across {len(results)} feeds -> {OUT_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

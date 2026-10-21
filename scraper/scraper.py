#!/usr/bin/env python3
"""
Sukhi CVIN Scrapper — harvests CERT-In Vulnerability Notes (CIVN) into Supabase.

Usage
-----
  python scraper.py incremental                     # daily: new notes from the current year
  python scraper.py backfill --from 2003 --to 2026  # history (resumable; skips rows already stored)
  python scraper.py note CIVN-2026-0508             # one note
  add --dry-run to any command to print JSON instead of writing to Supabase

Environment
-----------
  SUPABASE_URL   https://<project>.supabase.co
  SUPABASE_KEY   service_role / secret key (server-side only, never in the frontend)

How the site works (verified Oct 2026)
--------------------------------------
* Year listing: /s2cMainServlet?pageid=VLNLIST02&year=YYYY shows 20 notes, newest first.
* The site's own "Next >>" links (/VulNotesList.jsp?next=20) depend on a server session and
  break from scripts. Instead we use the stateless ...&year=YYYY&next=N form; an offset past
  the end (next=100000) returns the entire year on one page.
* Detail: /s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-YYYY-NNNN. Section headings are
  elements whose class contains "verblue" (e.g. <p class="contentTD; verblue">Solution</p>).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, NavigableString, Tag

log = logging.getLogger("cvin")

# --------------------------------------------------------------------------- constants
BASE = "https://www.cert-in.org.in"
LIST_URL = BASE + "/s2cMainServlet?pageid=VLNLIST02&year={year}"
LIST_PAGE_URL = BASE + "/s2cMainServlet?pageid=VLNLIST02&year={year}&next={offset}"  # stateless paging
PAGE_SIZE = 20
ALL_OFFSET = 100000  # offset past the end → CERT-In returns the whole year on one page
DETAIL_URL = BASE + "/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE={civn}"
FIRST_YEAR = 2003
USER_AGENT = (
    "SukhiCVINScrapper/1.0 (+https://github.com/; public advisory indexer; "
    "polite: 1 req/s) python-requests"
)

CIVN_RE = re.compile(r"CIVN-(\d{4})-(\d+)")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CWE_RE = re.compile(r"CWE-\d+")
DATE_RE = re.compile(r"([A-Za-z]+)\s+(\d{1,2})\s*,\s*(\d{4})")
SEVERITY_RE = re.compile(r"Severity\s+Rating\s*:?\s*([A-Za-z]+)", re.I)
HEADING_CLASS_RE = re.compile(r"\bverblue\b", re.I)  # matches "verblue", not "verblue2"
NOT_FOUND_RE = re.compile(r"requested URL is not found", re.I)
MARK = "\x00H\x00"

SECTION_ALIASES: dict[str, tuple[str, ...]] = {
    "software_affected": ("systems affected", "software affected", "products affected",
                          "affected products", "affected software", "platforms affected",
                          "component affected", "components affected"),
    "overview": ("overview",),
    "impact": ("impact", "impact assessment"),
    "description": ("description", "details"),
    "workaround": ("workaround", "workarounds", "mitigation"),
    "solution": ("solution", "solutions"),
    "vendor_information": ("vendor information",),
    "references": ("references", "reference"),
    "cve_names": ("cve name", "cve names", "cve id", "cve ids"),
    "cwe_names": ("cwe name", "cwe names"),
}
HEADING_TO_KEY = {alias: key for key, aliases in SECTION_ALIASES.items() for alias in aliases}
STOP_HEADINGS = ("disclaimer", "contact information", "postal address")
BLOCK_TAGS = ("p", "div", "li", "ul", "ol", "tr", "table", "tbody", "h1", "h2", "h3", "h4", "h5", "h6")
TEXT_COLUMNS = ("software_affected", "overview", "impact", "description",
                "workaround", "solution", "vendor_information")


# --------------------------------------------------------------------------- models
@dataclass
class ListingEntry:
    civn_id: str
    published_date: str | None = None
    title: str | None = None


@dataclass
class Note:
    civn_id: str
    year: int
    title: str
    published_date: str | None
    severity: str | None
    software_affected: str | None = None
    overview: str | None = None
    impact: str | None = None
    description: str | None = None
    workaround: str | None = None
    solution: str | None = None
    vendor_information: str | None = None
    reference_urls: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    other_sections: dict[str, str] = field(default_factory=dict)
    source_url: str = ""
    last_scraped_at: str = ""

    def to_row(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- helpers
def parse_date(text: str | None) -> str | None:
    """'October   21, 2026' / '(May 01, 2008)' -> '2026-10-21'."""
    if not text:
        return None
    m = DATE_RE.search(text.replace("\xa0", " "))
    if not m:
        return None
    month, day, year = m.groups()
    for candidate, fmt in ((month, "%B"), (month[:3], "%b")):  # "October" or "Oct"/"Sept"
        try:
            return dt.datetime.strptime(f"{candidate} {day} {year}", f"{fmt} %d %Y").date().isoformat()
        except ValueError:
            continue
    return None


def clean_line(s: str) -> str:
    return re.sub(r"[ \t\r\f\v\xa0]+", " ", s).strip()


def clean_block(s: str) -> str:
    lines = [clean_line(x) for x in s.split("\n")]
    out: list[str] = []
    for line in lines:
        if line:
            out.append(line)
    text = "\n".join(out)
    text = re.sub(r"\(\s*\n\s*", "(", text)    # "(\nCVE-x" -> "(CVE-x"
    text = re.sub(r"\s*\n\s*\)", ")", text)
    return text.strip()


def uniq(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def is_heading(tag) -> bool:
    if not isinstance(tag, Tag):
        return False
    cls = tag.get("class")
    if not cls:
        return False
    return bool(HEADING_CLASS_RE.search(" ".join(cls) if isinstance(cls, list) else str(cls)))


def normalise_heading(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip().strip(":").strip().lower()


# --------------------------------------------------------------------------- parsers
def parse_listing(html: str) -> tuple[list[ListingEntry], str | None]:
    """Return (entries on this page, absolute URL of the next page or None)."""
    soup = BeautifulSoup(html, "html.parser")
    root = soup.find(id="print_content") or soup
    entries: list[ListingEntry] = []
    seen: set[str] = set()

    for a in root.find_all("a", href=True):
        m = re.search(r"VLCODE=(CIVN-\d{4}-\d+)", a["href"])
        if not m or m.group(1) in seen:
            continue
        civn = m.group(1)
        seen.add(civn)
        entry = ListingEntry(civn_id=civn)
        table = a.find_parent("table")
        if table:
            date_el = table.find(class_="DateContent")
            if date_el:
                entry.published_date = parse_date(date_el.get_text(" "))
            for td in table.find_all("td"):
                txt = clean_line(td.get_text(" "))
                if (not txt or "CIVN-" in txt
                        or (date_el and date_el in td.descendants)):
                    continue
                entry.title = txt
                break
        entries.append(entry)

    next_url = None
    for a in soup.find_all("a", href=True):
        if "VulNotesList.jsp" in a["href"] and "next" in a.get_text(" ").lower():
            next_url = urljoin(BASE + "/", a["href"].strip())
            break
    return entries, next_url


def parse_detail(html: str, civn_id: str, listing: ListingEntry | None = None) -> Note:
    soup = BeautifulSoup(html, "html.parser")
    root = soup.find(id="print_content")
    if root is None:
        raise ValueError(f"{civn_id}: no #print_content on page (layout changed or not found)")
    if NOT_FOUND_RE.search(root.get_text(" ")) and civn_id not in root.get_text(" "):
        raise ValueError(f"{civn_id}: CERT-In returned 'not found'")

    # Collect links per section *before* mutating the tree.
    headings = [t for t in root.find_all(is_heading) if not any(is_heading(p) for p in t.parents)]
    heading_ids = {id(h) for h in headings}

    def section_of(el) -> str:
        prev = el if id(el) in heading_ids else el.find_previous(lambda t: isinstance(t, Tag) and id(t) in heading_ids)
        if prev is None:
            return "_header"
        first = prev.get_text("\n").strip().split("\n")[0]
        h = normalise_heading(first)
        return HEADING_TO_KEY.get(h, h)

    links_by_section: dict[str, list[str]] = {}
    all_hrefs: list[str] = []
    for a in root.find_all("a", href=True):
        href = a["href"].strip()
        all_hrefs.append(href)
        links_by_section.setdefault(section_of(a), []).append(href)

    # Turn layout into newline-separated text, then split on heading markers.
    for br in root.find_all("br"):
        br.replace_with(NavigableString("\n"))
    for tag in root.find_all(BLOCK_TAGS):
        tag.insert_before(NavigableString("\n"))
        tag.insert_after(NavigableString("\n"))
        if tag.name == "li":
            tag.insert(0, NavigableString("• "))
    for h in headings:
        h.insert_before(NavigableString(MARK))

    full_text = root.get_text()
    chunks = full_text.split(MARK)
    header = clean_block(chunks[0])

    sections: dict[str, str] = {}
    other: dict[str, str] = {}
    for chunk in chunks[1:]:
        body = clean_block(chunk)
        if not body:
            continue
        head, _, rest = body.partition("\n")
        h = normalise_heading(head)
        if h.startswith(STOP_HEADINGS):
            break
        key = HEADING_TO_KEY.get(h)
        rest = rest.strip()
        if key:
            sections[key] = (sections[key] + "\n\n" + rest).strip() if key in sections else rest
        elif rest:
            other[head.strip(" :")] = rest

    # Header: "CERT-In Vulnerability Note CIVN-…", title, "Original Issue Date:…", "Severity Rating: …"
    title = None
    for line in header.split("\n"):
        if CIVN_RE.search(line) or re.match(r"(?i)(cert-in )?vulnerability note$", line):
            continue
        if re.match(r"(?i)original issue date|severity rating", line):
            break
        title = line
        break
    title = (title or (listing.title if listing else None) or civn_id).rstrip(" .") or civn_id

    date_m = re.search(r"Original\s+Issue\s+Date\s*:?(.*)", header, re.I)
    published = parse_date(date_m.group(1)) if date_m else None
    if not published and listing:
        published = listing.published_date

    sev_m = SEVERITY_RE.search(header)
    severity = sev_m.group(1).upper() if sev_m else None

    # IDs: scan visible text of the note (minus boilerplate) and all hrefs.
    note_text = header + "\n" + "\n".join(sections.values()) + "\n" + "\n".join(other.values())
    haystack = note_text + "\n" + "\n".join(all_hrefs)
    cve_ids = sorted(set(CVE_RE.findall(haystack.upper())))
    cwe_ids = sorted(set(CWE_RE.findall(note_text.upper())))

    ref_links = (links_by_section.get("references", []) + links_by_section.get("vendor_information", [])
                 + links_by_section.get("solution", []))
    reference_urls = uniq(
        u for u in ref_links
        if u.lower().startswith("http") and "cert-in.org.in" not in u.lower()
        and not CVE_RE.search(u.upper()) and "cwe.mitre.org" not in u.lower()
    )

    year = int(CIVN_RE.search(civn_id).group(1))
    return Note(
        civn_id=civn_id,
        year=year,
        title=title,
        published_date=published,
        severity=severity,
        reference_urls=reference_urls,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        other_sections=other,
        source_url=DETAIL_URL.format(civn=civn_id),
        last_scraped_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        **{k: (sections.get(k) or None) for k in TEXT_COLUMNS},
    )


# --------------------------------------------------------------------------- CERT-In client
class RetryableHTTP(Exception):
    pass


class CertInClient:
    def __init__(self, delay: float = 1.0, timeout: float = 60.0, retries: int = 4):
        self.delay, self.timeout, self.retries = delay, timeout, retries
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-IN,en;q=0.8"})
        # Stateless URLs need no session. Observed on GitHub runners: once a JSESSIONID cookie was
        # held, CERT-In stopped answering (read timeouts), so never store cookies.
        from http.cookiejar import DefaultCookiePolicy
        self.session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        self._last = 0.0

    def get(self, url: str) -> str:
        for attempt in range(1, self.retries + 1):
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code in (429, 500, 502, 503, 504):
                    raise RetryableHTTP(f"HTTP {r.status_code}")
                r.raise_for_status()
                if not r.encoding or r.encoding.lower() == "iso-8859-1":
                    r.encoding = "utf-8" if b"charset=utf-8" in r.content[:2000].lower() else "windows-1252"
                return r.text
            except (requests.ConnectionError, requests.Timeout, RetryableHTTP) as e:
                if attempt == self.retries:
                    raise
                backoff = min(60, 2 ** attempt)
                log.warning("GET %s failed (%s); retry %d/%d in %ss", url, e, attempt, self.retries - 1, backoff)
                time.sleep(backoff)
        raise RuntimeError("unreachable")

    def list_year(self, year: int, stop_when: Callable[[list[ListingEntry]], bool] | None = None,
                  max_pages: int = 200) -> list[ListingEntry]:
        """All listing entries for a year (newest first).

        Uses the stateless URL  ...pageid=VLNLIST02&year=Y&next=N  (no session needed).
        Fast path: an offset past the end makes CERT-In return the whole year in one page.
        Fallback: walk offsets 0, 20, 40 ... until a short/empty page (stops early if stop_when(page)).
        """
        def year_entries(html: str, seen: set[str]) -> list[ListingEntry]:
            entries, _ = parse_listing(html)
            return [e for e in entries if e.civn_id not in seen and e.civn_id.startswith(f"CIVN-{year}-")]

        try:
            full = year_entries(self.get(LIST_PAGE_URL.format(year=year, offset=ALL_OFFSET)), set())
            nums = [int(e.civn_id.rsplit("-", 1)[1]) for e in full]
            if full and len(full) > PAGE_SIZE and len(set(nums)) >= 0.95 * max(nums):
                log.info("%s: full listing in one request → %d notes", year, len(full))
                return full
            log.info("%s: one-page listing returned %d notes; paging instead", year, len(full))
        except Exception as ex:
            log.warning("%s: one-page listing failed (%s); paging instead", year, ex)

        out: list[ListingEntry] = []
        seen: set[str] = set()
        for page_no in range(max_pages):
            page = year_entries(self.get(LIST_PAGE_URL.format(year=year, offset=page_no * PAGE_SIZE)), seen)
            if not page:
                break
            seen.update(e.civn_id for e in page)
            out.extend(page)
            log.info("%s: listing page %d → %d notes (total %d)", year, page_no + 1, len(page), len(out))
            if len(page) < PAGE_SIZE or (stop_when and stop_when(page)):
                break
        return out

    def fetch_note(self, civn_id: str, listing: ListingEntry | None = None) -> Note:
        return parse_detail(self.get(DETAIL_URL.format(civn=civn_id)), civn_id, listing)


# --------------------------------------------------------------------------- Supabase REST
class Supabase:
    def __init__(self, url: str, key: str, timeout: float = 30.0):
        self.rest = url.rstrip("/") + "/rest/v1"
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update({"apikey": key, "Content-Type": "application/json"})
        if key.startswith("eyJ"):  # legacy JWT keys also go in Authorization; new sb_secret_ keys don't
            self.s.headers["Authorization"] = f"Bearer {key}"

    def _check(self, r: requests.Response) -> requests.Response:
        if r.status_code >= 400:
            raise RuntimeError(f"Supabase {r.request.method} {r.url} → {r.status_code}: {r.text[:500]}")
        return r

    def existing_ids(self, year: int) -> set[str]:
        ids: set[str] = set()
        offset, page = 0, 1000
        while True:
            r = self._check(self.s.get(f"{self.rest}/vulnerability_notes", timeout=self.timeout, params={
                "select": "civn_id", "year": f"eq.{year}", "order": "civn_id",
                "limit": page, "offset": offset}))
            rows = r.json()
            ids.update(x["civn_id"] for x in rows)
            if len(rows) < page:
                return ids
            offset += page

    def upsert_notes(self, rows: list[dict], batch: int = 50) -> int:
        n = 0
        for i in range(0, len(rows), batch):
            chunk = rows[i:i + batch]
            self._check(self.s.post(
                f"{self.rest}/vulnerability_notes", params={"on_conflict": "civn_id"},
                headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
                data=json.dumps(chunk), timeout=self.timeout))
            n += len(chunk)
        return n

    def start_run(self, mode: str, years: list[int]) -> int | None:
        r = self._check(self.s.post(f"{self.rest}/sync_runs", headers={"Prefer": "return=representation"},
                                    data=json.dumps({"mode": mode, "years": years}), timeout=self.timeout))
        return r.json()[0]["id"]

    def finish_run(self, run_id: int | None, **fields) -> None:
        if run_id is None:
            return
        fields["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self._check(self.s.patch(f"{self.rest}/sync_runs", params={"id": f"eq.{run_id}"},
                                 data=json.dumps(fields), timeout=self.timeout))


KEY_CHARS_RE = re.compile(r"[A-Za-z0-9._\-]")


def clean_supabase_key(raw: str) -> str:
    """Remove pasted whitespace/line breaks; explain (without revealing the key) if it's still malformed."""
    key = re.sub(r"\s+", "", raw)
    if key.lower().startswith("bearer"):
        key = key[6:]
    if key.startswith("sb_secret_"):
        kind = "new secret key (sb_secret_…)"
    elif key.startswith("sb_publishable_"):
        kind = "PUBLISHABLE key — wrong one, writes will be rejected"
    elif key.startswith("eyJ"):
        kind = "legacy JWT key"
        try:
            import base64
            payload = key.split(".")[1]
            role = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("role")
            kind += f" (role={role})" + ("" if role == "service_role" else " — wrong one, use service_role")
        except Exception:
            kind += " (could not decode)"
    else:
        kind = "unrecognised format"
    bad = sorted({"non-ASCII" if ord(c) > 127 else repr(c) for c in key if not KEY_CHARS_RE.match(c)})
    if bad or not key:
        raise ValueError(f"SUPABASE_KEY is malformed: length={len(key)}, looks like {kind}, "
                         f"unexpected characters: {', '.join(bad) or 'none'}. Re-copy it with Supabase's copy button.")
    if "wrong one" in kind:
        log.warning("SUPABASE_KEY looks like a %s", kind)
    else:
        log.info("SUPABASE_KEY: %s, length %d", kind, len(key))
    return key


class DryRunSink:
    """Stand-in for Supabase that prints JSON lines (for local testing)."""

    def __init__(self, out=sys.stdout):
        self.out = out

    def existing_ids(self, year: int) -> set[str]:
        return set()

    def upsert_notes(self, rows: list[dict], batch: int = 50) -> int:
        for row in rows:
            self.out.write(json.dumps(row, ensure_ascii=False) + "\n")
        self.out.flush()
        return len(rows)

    def start_run(self, mode, years):
        return None

    def finish_run(self, run_id, **fields):
        log.info("run summary: %s", fields)


# --------------------------------------------------------------------------- orchestration
@dataclass
class Stats:
    listed: int = 0
    new: int = 0
    upserted: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)


def harvest(client: CertInClient, sink, entries: list[ListingEntry], stats: Stats,
            deadline: float | None, flush_every: int = 25) -> bool:
    """Fetch details for entries and upsert in batches. Returns False if the deadline hit."""
    buf: list[dict] = []
    finished = True
    for i, e in enumerate(entries, 1):
        if deadline and time.monotonic() > deadline:
            log.warning("time budget reached; stopping early (resume by re-running)")
            finished = False
            break
        try:
            note = client.fetch_note(e.civn_id, e)
            buf.append(note.to_row())
            log.info("[%d/%d] %s %s | %s | %d CVEs", i, len(entries), note.civn_id,
                     note.published_date, note.severity, len(note.cve_ids))
        except Exception as ex:  # keep going; one bad page must not kill the run
            stats.failed += 1
            stats.failures.append(f"{e.civn_id}: {ex}")
            log.error("failed %s: %s", e.civn_id, ex)
        if len(buf) >= flush_every:
            stats.upserted += sink.upsert_notes(buf)
            buf = []
    if buf:
        stats.upserted += sink.upsert_notes(buf)
    return finished


def run(args) -> int:
    client = CertInClient(delay=args.delay)
    if args.dry_run:
        sink = DryRunSink(open(args.out, "w", encoding="utf-8") if args.out else sys.stdout)
    else:
        url = (os.environ.get("SUPABASE_URL") or "").strip().rstrip("/")
        key = os.environ.get("SUPABASE_KEY") or ""
        if not url or not key.strip():
            log.error("SUPABASE_URL and SUPABASE_KEY must be set (or use --dry-run)")
            return 2
        try:
            key = clean_supabase_key(key)
        except ValueError as ex:
            log.error("%s", ex)
            return 2
        if not re.fullmatch(r"https://[a-z0-9-]+\.supabase\.(co|in)", url):
            log.warning("SUPABASE_URL doesn't look like https://<ref>.supabase.co — check the secret")
        sink = Supabase(url, key)

    today = dt.date.today()
    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    stats = Stats()

    if args.command == "note":
        years = [int(CIVN_RE.search(c).group(1)) for c in args.civn_ids]
    elif args.command == "incremental":
        years = [today.year] + ([today.year - 1] if today.month == 1 and today.day <= 15 else [])
    else:
        years = list(range(max(args.year_from, FIRST_YEAR), min(args.year_to, today.year) + 1))
        if args.newest_first:
            years.reverse()

    run_id = sink.start_run(args.command, years)
    status, message = "success", None
    try:
        if args.command == "note":
            entries = [ListingEntry(c.upper()) for c in args.civn_ids]
            stats.listed = stats.new = len(entries)
            harvest(client, sink, entries, stats, deadline)
        else:
            for year in years:
                known = set() if args.force else sink.existing_ids(year)
                if args.command == "incremental":
                    # Newest first: stop paging once a whole page is already stored.
                    listed = client.list_year(year, stop_when=lambda page: all(e.civn_id in known for e in page))
                    todo = [e for e in listed if e.civn_id not in known]
                    todo += [e for e in listed[: args.recheck] if e.civn_id in known]  # pick up CERT-In revisions
                else:
                    listed = client.list_year(year)
                    todo = [e for e in listed if e.civn_id not in known]
                stats.listed += len(listed)
                stats.new += sum(1 for e in todo if e.civn_id not in known)
                log.info("%s: %d listed, %d to fetch", year, len(listed), len(todo))
                if not harvest(client, sink, todo, stats, deadline):
                    status, message = "partial", "time budget reached"
                    break
        if stats.failed:
            status = "partial" if stats.upserted else "failed"
            message = "; ".join(stats.failures[:20])
    except Exception as ex:
        status, message = "failed", f"{type(ex).__name__}: {ex}"
        log.exception("run failed")
    finally:
        sink.finish_run(run_id, status=status, message=message, notes_listed=stats.listed,
                        notes_new=stats.new, notes_upserted=stats.upserted, notes_failed=stats.failed)

    log.info("done: status=%s listed=%d new=%d upserted=%d failed=%d",
             status, stats.listed, stats.new, stats.upserted, stats.failed)
    return 0 if status != "failed" else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sukhi CVIN Scrapper — CERT-In vulnerability notes → Supabase")
    p.add_argument("--dry-run", action="store_true", help="print JSON lines instead of writing to Supabase")
    p.add_argument("--out", help="with --dry-run: write JSON lines to this file")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between requests to CERT-In (default 1.0)")
    p.add_argument("--max-minutes", type=float, default=0, help="stop cleanly after N minutes (0 = no limit)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    inc = sub.add_parser("incremental", help="fetch notes not yet stored from the current year")
    inc.add_argument("--recheck", type=int, default=5, help="also re-fetch the newest N stored notes (default 5)")
    inc.add_argument("--force", action="store_true", help="re-fetch everything in the current year")

    bf = sub.add_parser("backfill", help="historical backfill across a year range")
    bf.add_argument("--from", dest="year_from", type=int, default=FIRST_YEAR)
    bf.add_argument("--to", dest="year_to", type=int, default=dt.date.today().year)
    bf.add_argument("--force", action="store_true", help="re-fetch notes already stored")
    bf.add_argument("--newest-first", action="store_true", help="process years from newest to oldest")

    one = sub.add_parser("note", help="fetch specific notes by CIVN ID")
    one.add_argument("civn_ids", nargs="+")

    args = p.parse_args(argv)
    if args.command == "note":
        args.force = True
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

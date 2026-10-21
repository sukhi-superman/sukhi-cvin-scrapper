# Sukhi CVIN Scrapper

Free, self-updating index of CERT-In Vulnerability Notes (CIVN) — Supabase + GitHub Actions + GitHub Pages.

## Layout
| Path | What |
|---|---|
| `supabase/schema.sql` | Tables, search function, read-only security. Run once in Supabase SQL Editor. |
| `scraper/scraper.py` | Scraper: `incremental`, `backfill`, `note` modes (`--dry-run` to test). |
| `.github/workflows/daily_sync.yml` | Daily run at 06:47 IST + manual trigger + schedule keep-alive. |
| `.github/workflows/backfill.yml` | Manual, resumable history backfill (2003 → now). |
| `tests/` | Offline parser tests on saved CERT-In pages. |

## Setup
1. **Supabase**: create a project → SQL Editor → paste `supabase/schema.sql` → Run.
2. **GitHub**: push this folder to a repo → Settings → Secrets and variables → Actions → add
   - `SUPABASE_URL` — Project URL
   - `SUPABASE_KEY` — **service_role / secret** key (never use this in the dashboard)
3. **First test**: Actions → *Daily CVIN sync* → Run workflow. Check the run summary.
4. **History**: Actions → *Historical backfill* → Run workflow (defaults: 2003 → now, newest first).
   It stops cleanly at ~5.5 h; re-run with the same inputs to continue. Expect 2–3 runs.

## Local use
```bash
pip3 install -r requirements.txt
python3 tests/test_parsing.py
python3 scraper/scraper.py --dry-run note CIVN-2026-0508          # print one note as JSON
python3 scraper/scraper.py --dry-run --out 2026.jsonl incremental  # current year, no DB writes
```

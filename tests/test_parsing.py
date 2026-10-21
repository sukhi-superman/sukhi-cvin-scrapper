"""Offline parser tests against HTML captured from cert-in.org.in (Oct 2026).

Run:  python -m pytest tests -q      (or: python tests/test_parsing.py)
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scraper"))
import scraper as s  # noqa: E402

FX = ROOT / "tests" / "fixtures"


def load(name):
    return (FX / name).read_text(encoding="utf-8")


def test_listing():
    entries, nxt = s.parse_listing(load("listing_2026.html"))
    assert [e.civn_id for e in entries] == ["CIVN-2026-0510", "CIVN-2026-0509"]
    assert entries[0].published_date == "2026-10-21"
    assert entries[0].title == "Critical remote code execution vulnerabilities in PHP"
    assert nxt == "https://www.cert-in.org.in/VulNotesList.jsp?next=40"


def test_detail_2026():
    n = s.parse_detail(load("detail_CIVN-2026-0508.html"), "CIVN-2026-0508")
    assert n.title == "Multiple Vulnerabilities in SonicWall SMA1000"
    assert n.published_date == "2026-10-19"
    assert n.severity == "CRITICAL"
    assert n.cve_ids == ["CVE-2026-102255", "CVE-2026-102256", "CVE-2026-102257", "CVE-2026-102258"]
    assert "SMA 1000" in n.software_affected
    assert "Target Audience" in n.overview
    assert n.solution.startswith("Apply appropriate updates")
    assert "https://psirt.global.sonicwall.com/vuln-list" in n.reference_urls
    assert not any("cve.org" in u for u in n.reference_urls)
    assert "Disclaimer" not in (n.description or "")


def test_detail_2008_merged_cve_cwe_links():
    n = s.parse_detail(load("detail_CIVN-2008-0050.html"), "CIVN-2008-0050")
    assert n.published_date == "2008-05-01"
    assert n.severity == "HIGH"
    assert n.cve_ids == ["CVE-2008-1761", "CVE-2008-1762"]
    assert n.cwe_ids == ["CWE-399"]
    assert n.software_affected == "• Opera versions prior to 9.27"
    assert "http://www.securityfocus.com/bid/28585" in n.reference_urls


def test_detail_2003_old_layout():
    n = s.parse_detail(load("detail_CIVN-2003-0016.html"), "CIVN-2003-0016")
    assert n.title == "Microsoft Internet Explorer does not properly display URLs"
    assert n.published_date == "2003-12-31"
    assert n.severity == "MEDIUM"
    assert n.cve_ids == []
    assert n.impact.startswith("The vulnerability exposes")
    assert n.workaround.startswith("Do not click")
    assert n.reference_urls[0] == "http://www.kb.cert.org/vuls/id/652278"


def test_parse_date_variants():
    assert s.parse_date("(October   21, 2026)") == "2026-10-21"
    assert s.parse_date("Sept 3, 2019") == "2019-09-03"
    assert s.parse_date("garbage") is None


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)

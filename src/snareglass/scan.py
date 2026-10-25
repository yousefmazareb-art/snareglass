"""Orchestration: turn a message, file or URL into a scored Report."""
from __future__ import annotations

import base64
import email
import re
from email import policy

from .files import analyze_file
from .headers import analyze_headers
from .models import Finding, Report
from .urls import analyze_url, extract_html_links, extract_urls

MAX_URLS = 50

BODY_PATTERNS = [
    (r"(?i)seed phrase|recovery phrase|private key|secret recovery", "high", "BODY_CRYPTO_SECRET", "Asks for a crypto seed phrase or private key (legitimate services never do)."),
    (r"(?i)\b(password|passcode|one[- ]time code|2fa code|ssn|social security)\b", "medium", "BODY_CREDENTIALS", "Mentions passwords, codes or ID numbers."),
    (r"(?i)(urgent|immediately|within \d+ hours|final notice|act now|last warning)", "low", "BODY_URGENCY", "Uses urgency or pressure language."),
    (r"(?i)(account (will be |has been )?(suspended|locked|closed|limited|compromised)|unusual (sign[- ]in|activity)|verify your (account|identity))", "medium", "BODY_ACCOUNT_THREAT", "Threatens account problems to push you to click."),
    (r"(?i)(gift cards?|wire transfer|western union|bitcoin|crypto payment)", "medium", "BODY_PAYMENT", "Asks for hard-to-reverse payment methods."),
    (r"(?i)(you('ve| have) won|claim your (prize|reward)|lottery|inheritance)", "medium", "BODY_PRIZE", "Prize or windfall bait."),
]

CATEGORY_MAP = {
    "URL_BRAND_LOOKALIKE": "credential phishing",
    "URL_TEXT_MISMATCH": "link spoofing",
    "HDR_DISPLAY_NAME_SPOOF": "sender impersonation",
    "HDR_SPF_FAIL": "sender impersonation",
    "HDR_DKIM_FAIL": "sender impersonation",
    "HDR_DMARC_FAIL": "sender impersonation",
    "BODY_CRYPTO_SECRET": "crypto scam",
    "BODY_PAYMENT": "payment scam",
    "BODY_PRIZE": "prize scam",
    "HTML_PASSWORD_FORM": "credential phishing",
    "OFFICE_MACROS": "malware delivery",
    "EXT_DOUBLE": "malware delivery",
    "TYPE_MISMATCH": "malware delivery",
    "FILE_EXECUTABLE": "malware delivery",
    "SCRIPT_PS_ENCODED": "malware delivery",
    "SCRIPT_PIPE_SHELL": "malware delivery",
    "ZIP_CONTAINS_EXECUTABLE": "malware delivery",
}


def finalize(report: Report) -> Report:
    findings = report.all_findings()
    report.score = min(100, sum(f.points for f in findings))
    if any(f.severity == "critical" for f in findings):
        report.score = max(report.score, 70)
    s = report.score
    report.verdict = "DANGEROUS" if s >= 70 else "SUSPICIOUS" if s >= 35 else "CAUTION" if s >= 10 else "LIKELY SAFE"
    cats = {CATEGORY_MAP[f.code] for f in findings if f.code in CATEGORY_MAP}
    report.categories = sorted(cats)
    return report


def _add_url(report: Report, seen: set, url: str, text: str | None = None) -> None:
    if url in seen or len(seen) >= MAX_URLS:
        return
    seen.add(url)
    report.urls.append(analyze_url(url, text))


def scan_message(sender: str = "", subject: str = "", body: str = "", html: str = "",
                 attachments: list[tuple[str, bytes]] | None = None, headers_findings: list[Finding] | None = None) -> Report:
    r = Report(sender=sender, subject=subject)
    r.findings += headers_findings or []
    seen: set[str] = set()
    for pat, sev, code, detail in BODY_PATTERNS:
        if re.search(pat, f"{subject}\n{body}\n{re.sub(r'<[^>]+>', ' ', html)}"):
            r.findings.append(Finding(sev, code, detail))
    if html:
        links, forms = extract_html_links(html)
        for href, text in links:
            _add_url(r, seen, href, text)
        for action in forms:
            r.findings.append(Finding("high", "HTML_FORM_EXTERNAL", f"Email contains a form that submits to {action[:80]}."))
    for u in extract_urls(body):
        _add_url(r, seen, u)
    for name, data in attachments or []:
        fr = analyze_file(name, data)
        r.files.append(fr)
        for u in fr.urls:
            _add_url(r, seen, u)
    return finalize(r)


def scan_eml(data: bytes) -> Report:
    msg = email.message_from_bytes(data, policy=policy.default)
    body = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    atts = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        atts.append((part.get_filename() or "unnamed", payload))
    return scan_message(
        sender=str(msg.get("From", "")), subject=str(msg.get("Subject", "")),
        body=body.get_content() if body else "", html=html.get_content() if html else "",
        attachments=atts, headers_findings=analyze_headers(msg),
    )


def scan_url(url: str) -> Report:
    r = Report()
    r.urls.append(analyze_url(url))
    return finalize(r)


def scan_file(name: str, data: bytes) -> Report:
    return scan_message(attachments=[(name, data)])


def scan_file_b64(name: str, b64: str) -> Report:
    return scan_file(name, base64.b64decode(b64))

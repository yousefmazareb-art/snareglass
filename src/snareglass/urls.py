"""Link analysis. Pure string inspection: nothing is ever fetched or opened."""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import Finding, UrlReport

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'\)\]]+""")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "s.id", "t.ly",
}
RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "gq", "tk", "ml", "cf", "ga", "work",
    "support", "country", "kim", "loan", "rest", "monster", "icu", "cyou",
}
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "co.in", "com.br", "co.nz", "co.za", "com.mx"}
LOGIN_WORDS = re.compile(r"(?i)(login|log-in|signin|sign-in|verify|secure|update|account|password|wallet|recover)")

OFFICIAL: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "windows.com", "azure.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl", "google.co.uk"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.ca"},
    "netflix": {"netflix.com"},
    "github": {"github.com", "github.io", "githubusercontent.com", "githubassets.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "binance": {"binance.com"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "anthropic": {"anthropic.com", "claude.ai"},
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def brand_lookalike(host: str) -> str | None:
    """Return the brand a host imitates (but does not own), else None."""
    reg = registered_domain(host)
    flat = host.lower().replace("-", "").replace(".", "")
    norm = flat.replace("rn", "m").translate(_LEET)
    for brand, official in OFFICIAL.items():
        if reg in official:
            continue
        if brand in flat or brand in norm:
            return brand
    return None


def analyze_url(url: str, display_text: str | None = None) -> UrlReport:
    raw = url.strip()
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    rep = UrlReport(url=url)
    f = rep.findings
    try:
        p = urlparse(raw)
    except ValueError:
        f.append(Finding("medium", "URL_MALFORMED", "URL could not be parsed."))
        return rep

    scheme = p.scheme.lower()
    if scheme in {"javascript", "data", "vbscript", "file"}:
        f.append(Finding("critical", "URL_DANGEROUS_SCHEME", f"Link uses the '{scheme}:' scheme, which can run code or open local content."))
        return rep

    host = (p.hostname or "").lower()
    rep.host = host
    if not host:
        return rep

    if scheme == "http":
        f.append(Finding("low", "URL_NO_TLS", "Link is not encrypted (http)."))
    if "@" in p.netloc:
        f.append(Finding("high", "URL_USERINFO", "Link contains user@host trickery: the text before '@' is ignored by browsers and used to disguise the real site."))
    try:
        ipaddress.ip_address(host)
        f.append(Finding("medium", "URL_IP_HOST", "Link points at a raw IP address instead of a domain."))
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        f.append(Finding("medium", "URL_PUNYCODE", "Domain uses punycode (xn--), often used for look-alike characters."))
    if any(ord(c) > 127 for c in host):
        f.append(Finding("medium", "URL_NON_ASCII", "Domain contains non-ASCII characters (possible homograph attack)."))
    reg = registered_domain(host)
    if reg in SHORTENERS or host in SHORTENERS:
        f.append(Finding("medium", "URL_SHORTENER", f"Link hides its destination behind a URL shortener ({reg})."))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        f.append(Finding("low", "URL_RISKY_TLD", f"Domain ends in .{tld}, a TLD frequently abused for throwaway sites."))
    if host.count(".") >= 4:
        f.append(Finding("low", "URL_DEEP_SUBDOMAIN", "Unusually many subdomains, a common trick to push the real domain out of sight."))
    if len(raw) > 200:
        f.append(Finding("low", "URL_VERY_LONG", "Very long URL."))
    if p.port and p.port not in (80, 443):
        f.append(Finding("low", "URL_ODD_PORT", f"Link uses a non-standard port ({p.port})."))

    brand = brand_lookalike(host)
    if brand:
        f.append(Finding("high", "URL_BRAND_LOOKALIKE", f"Domain '{host}' imitates {brand} but is not an official {brand} domain."))
    elif LOGIN_WORDS.search(p.path + (p.query or "")) and not any(reg in d for d in OFFICIAL.values()):
        f.append(Finding("low", "URL_LOGIN_PATH", "Link path looks like a login/verification page on an unfamiliar domain."))

    if display_text:
        m = URL_RE.search(display_text) or re.search(r"(?i)\b[a-z0-9-]+(\.[a-z0-9-]+)+\b", display_text)
        if m:
            shown = m.group(0)
            shown_host = urlparse(shown if "//" in shown else "http://" + shown).hostname or ""
            if shown_host and registered_domain(shown_host) != reg:
                f.append(Finding("high", "URL_TEXT_MISMATCH", f"Link text shows '{shown_host}' but actually goes to '{host}'."))
    return rep


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.forms: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "form" and a.get("action"):
            self.forms.append(a["action"])
        elif tag in {"img", "iframe"} and (a.get("src") or "").startswith("http"):
            self.links.append((a["src"], ""))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def extract_html_links(html: str) -> tuple[list[tuple[str, str]], list[str]]:
    p = _LinkParser()
    try:
        p.feed(html)
    except Exception:
        pass
    return p.links, p.forms


def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]

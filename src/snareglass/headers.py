"""Email header checks: spoofing, reply-to tricks, failed authentication."""
from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses, parseaddr

from .models import Finding
from .urls import OFFICIAL, registered_domain


def _domain(addr: str) -> str:
    addr = parseaddr(addr)[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def analyze_headers(msg: Message) -> list[Finding]:
    out: list[Finding] = []
    from_hdr = msg.get("From", "")
    name, addr = parseaddr(from_hdr)
    from_dom = _domain(from_hdr)

    reply_to = [d for _, d in getaddresses(msg.get_all("Reply-To", [])) if d]
    for r in reply_to:
        rd = r.rsplit("@", 1)[-1].lower()
        if from_dom and registered_domain(rd) != registered_domain(from_dom):
            out.append(Finding("medium", "HDR_REPLYTO_MISMATCH", f"Replies go to {rd}, not the sender's domain ({from_dom})."))
            break

    rp = _domain(msg.get("Return-Path", ""))
    if rp and from_dom and registered_domain(rp) != registered_domain(from_dom):
        out.append(Finding("low", "HDR_RETURNPATH_MISMATCH", f"Return-Path domain ({rp}) differs from From domain ({from_dom}); can be normal for mailing services."))

    auth = " ".join(msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", [])).lower()
    if not auth:
        out.append(Finding("info", "HDR_NO_AUTH", "No SPF/DKIM/DMARC results in the headers (not available from every mail app)."))
    else:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}=(\w+)", auth)
            if m and m.group(1) in {"fail", "softfail", "permerror", "temperror"}:
                sev = "high" if m.group(1) == "fail" else "medium"
                out.append(Finding(sev, f"HDR_{mech.upper()}_FAIL", f"{mech.upper()} check result: {m.group(1)}. The sender may be forged."))

    low = name.lower().replace(" ", "")
    for brand, official in OFFICIAL.items():
        if brand in low and from_dom and registered_domain(from_dom) not in official:
            out.append(Finding("high", "HDR_DISPLAY_NAME_SPOOF", f"Sender name claims to be '{brand}' but the address is @{from_dom}."))
            break
    return out

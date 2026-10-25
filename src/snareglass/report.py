from __future__ import annotations

from .models import Report

ICON = {"LIKELY SAFE": "OK", "CAUTION": "CAUTION", "SUSPICIOUS": "SUSPICIOUS", "DANGEROUS": "DANGEROUS"}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def to_markdown(r: Report) -> str:
    L: list[str] = [f"## Verdict: {ICON[r.verdict]} (risk score {r.score}/100)"]
    if r.subject or r.sender:
        L.append(f"**From:** {r.sender or 'n/a'}  \n**Subject:** {r.subject or 'n/a'}")
    if r.categories:
        L.append("**Looks like:** " + ", ".join(r.categories))

    msg_f = sorted(r.findings, key=lambda f: ORDER[f.severity])
    if msg_f:
        L.append("### Message signals")
        L += [f"- **{f.severity.upper()}** `{f.code}`: {f.detail}" for f in msg_f]

    if r.urls:
        L.append("### Links")
        for u in r.urls:
            if u.findings:
                L.append(f"- `{u.url[:90]}`")
                L += [f"  - **{f.severity.upper()}**: {f.detail}" for f in sorted(u.findings, key=lambda f: ORDER[f.severity])]
            else:
                L.append(f"- `{u.url[:90]}`: no red flags found")

    if r.files:
        L.append("### Attachments")
        for f in r.files:
            L.append(f"- **{f.name}**: {f.description}, {_fmt_size(f.size)}  \n  sha256 `{f.sha256}`")
            L.append(f"  - Content preview: {f.preview or 'n/a'}")
            L += [f"  - **{x.severity.upper()}**: {x.detail}" for x in sorted(f.findings, key=lambda x: ORDER[x.severity])]
            if not f.findings:
                L.append("  - No risky traits found by static checks")

    L.append("### What to do")
    if r.verdict == "DANGEROUS":
        L.append("Do not click, open or reply. Delete it, and if you already interacted, change affected passwords and run a malware scan.")
    elif r.verdict == "SUSPICIOUS":
        L.append("Do not open links or files. Verify with the sender through a different channel (a phone number you already have).")
    elif r.verdict == "CAUTION":
        L.append("Minor warning signs. Open nothing you were not expecting and go to the site by typing the address yourself.")
    else:
        L.append("No strong warning signs, but static checks are not a guarantee. Stay careful with unexpected requests.")
    L.append("\n_Static analysis only: nothing was opened, run or visited._")
    return "\n\n".join(L)

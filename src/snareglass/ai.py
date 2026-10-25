"""Optional Claude explanation. Sends indicators only, never the email body or file contents."""
from __future__ import annotations

import json
import os

from .models import Report

PROMPT = (
    "You are a security assistant. Explain in plain language, in under 150 words, what this "
    "message/file scan means for a non-technical person and what they should do. Do not "
    "invent facts beyond the JSON."
)


def explain(report: Report) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError("Install with: pip install 'snareglass[ai]'") from e
    safe = {
        "verdict": report.verdict, "score": report.score, "categories": report.categories,
        "sender_domain": report.sender.rsplit("@", 1)[-1].strip("> ") if "@" in report.sender else "",
        "findings": [{"code": f.code, "severity": f.severity, "detail": f.detail} for f in report.all_findings()],
        "files": [{"type": f.description, "name": f.name} for f in report.files],
        "link_hosts": [u.host for u in report.urls],
    }
    client = anthropic.Anthropic()
    out = client.messages.create(
        model=os.environ.get("SNAREGLASS_MODEL", "claude-sonnet-5-5"),
        max_tokens=400,
        system=PROMPT,
        messages=[{"role": "user", "content": json.dumps(safe)}],
    )
    return "".join(b.text for b in out.content if b.type == "text")

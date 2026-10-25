from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import to_markdown
from .scan import scan_eml, scan_file, scan_url


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snareglass", description="Static phishing / malware inspector.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("eml", "scan a .eml email file"), ("file", "scan an attachment"), ("url", "scan a link")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("target")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--ai", action="store_true", help="add a plain-language Claude explanation (needs ANTHROPIC_API_KEY)")
    a = ap.parse_args(argv)

    if a.cmd == "url":
        rep = scan_url(a.target)
    else:
        data = Path(a.target).read_bytes()
        rep = scan_eml(data) if a.cmd == "eml" else scan_file(Path(a.target).name, data)

    if a.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(to_markdown(rep))
    if a.ai:
        from .ai import explain
        print("\n### Claude's explanation\n" + explain(rep))
    return {"LIKELY SAFE": 0, "CAUTION": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}[rep.verdict]


if __name__ == "__main__":
    sys.exit(main())

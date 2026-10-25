"""MCP server so Claude can call Snareglass on messages it reads from your connected apps."""
from __future__ import annotations

import base64
from pathlib import Path

from .report import to_markdown
from .scan import scan_file, scan_message, scan_url


def build():
    try:  # mcp >= 2
        from mcp.server.mcpserver import MCPServer as Server
    except ImportError:
        try:  # mcp 1.x
            from mcp.server.fastmcp import FastMCP as Server
        except ImportError as e:
            raise SystemExit("Install the MCP extra: pip install 'snareglass[mcp]'") from e

    mcp = Server("snareglass")

    @mcp.tool()
    def scan_email(sender: str = "", subject: str = "", body: str = "", html_body: str = "",
                   attachments_base64: dict[str, str] | None = None) -> str:
        """Inspect one message (text, optional HTML, optional attachments as {filename: base64}) for phishing and malware signs. Never opens links."""
        atts = [(n, base64.b64decode(b)) for n, b in (attachments_base64 or {}).items()]
        return to_markdown(scan_message(sender, subject, body, html_body, atts))

    @mcp.tool()
    def scan_link(url: str) -> str:
        """Check a single link for phishing traits without visiting it."""
        return to_markdown(scan_url(url))

    @mcp.tool()
    def scan_attachment(path: str) -> str:
        """Inspect a downloaded attachment on disk: real file type, macros, scripts, hidden executables, and a content preview."""
        p = Path(path).expanduser()
        return to_markdown(scan_file(p.name, p.read_bytes()))

    return mcp


def main() -> None:
    build().run()


if __name__ == "__main__":
    main()

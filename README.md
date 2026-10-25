# Snareglass

A local phishing, link and attachment inspector that plugs into Claude. Claude reads the messages from the apps **you** choose, Snareglass inspects them without ever opening anything, and Claude explains the result in plain language: is it phishing, what kind of file is this, what is it about, and can it harm my device.

> ## Requirement
> **This skill requires Claude to be linked to your email or to the app(s) you want checked** (for example Gmail through Claude's connectors). Snareglass cannot read your inbox on its own. It only analyzes what Claude hands it from the sources you approve.

## What it checks

| Area | Examples |
|---|---|
| Links | look-alike brands (`paypa1`), text vs real destination mismatch, `user@host` tricks, punycode/homographs, raw IPs, shorteners, risky TLDs, dangerous schemes |
| Sender | display-name spoofing, Reply-To mismatch, SPF / DKIM / DMARC failures |
| Message text | urgency, account threats, seed-phrase/credential requests, gift card and crypto payment bait |
| Attachments | real type from file contents (not the name), `.pdf.exe` and renamed executables, Office macros, remote templates, PDF JavaScript/Launch, password-protected archives, executables inside ZIPs, HTML password forms, encoded PowerShell and downloader scripts |
| Summary | file type, size, SHA-256, content preview, risk score 0-100, category (credential phishing, malware delivery, scam) |

Everything is **static analysis**: nothing is visited, opened, or executed, and scanning makes no network requests.

## Install

```bash
git clone https://github.com/<you>/snareglass && cd snareglass
python -m venv .venv && source .venv/bin/activate
pip install -e ".[mcp]"          # add ",ai" for the optional Claude explanation in the CLI
```

### Connect to Claude

1. **MCP server** (Claude Desktop): add to your config file
   ```json
   {
     "mcpServers": {
       "snareglass": { "command": "/full/path/to/.venv/bin/snareglass-mcp" }
     }
   }
   ```
   Restart Claude.
2. **Skill:** zip the `skill/` folder (`snareglass-skill.zip`, the folder must contain `SKILL.md`) and upload it under Claude's Skills settings.
3. **Link your sources:** connect Claude to your email or app in its connector settings, then tell Claude which ones to watch, for example *"Use Snareglass on my unread Gmail only."*

## Command line (no Claude needed)

```bash
snareglass eml examples/sample_phish.eml
snareglass file invoice.pdf
snareglass url "http://paypa1-secure-login.top/verify"
snareglass eml message.eml --json
snareglass eml message.eml --ai     # needs ANTHROPIC_API_KEY and the [ai] extra
```
Exit code: `0` safe/caution, `1` suspicious, `2` dangerous.

## Privacy

- You choose the sources; the skill instructs Claude to read nothing else and to act read-only.
- The optional `--ai` mode sends only indicators (finding codes, link hosts, file types), not message bodies or file contents.
- Set the model with `SNAREGLASS_MODEL`.

## Limits (honest)

Snareglass is a heuristic first line of defense, not an antivirus. It does not detonate files, follow redirects, or check reputation feeds, so a clean result is not a guarantee. Roadmap ideas: opt-in redirect unwinding, URLhaus/Safe Browsing lookups, YARA rules, QR-code extraction.

## Develop

```bash
pip install -e ".[dev]" && pytest
```

MIT licensed.

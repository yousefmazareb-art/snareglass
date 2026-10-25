# Security policy

Snareglass only performs static analysis: it never opens links, runs attachments, or executes macros.

Report vulnerabilities (for example a crafted file that crashes or hangs the scanner) privately through GitHub's "Report a vulnerability" button on the Security tab. Please do not open a public issue for these.

## Design guarantees
- No network requests are made while scanning.
- Attachment reading is capped at 25 MB.
- The optional `--ai` mode sends only indicators (finding codes, link hosts, file types), never message bodies or file contents.

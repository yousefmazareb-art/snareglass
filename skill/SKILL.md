---
name: snareglass
description: Check incoming messages from the apps the user has chosen (email, chat, etc.) for phishing, scam links and dangerous attachments, then give a plain-language summary. Use when the user asks to check, scan or triage messages, links or files for phishing or malware, or asks "is this safe?".
---

# Snareglass

Requires: Claude connected to the user's email or the app(s) they want watched, plus the Snareglass MCP server (tools: `scan_email`, `scan_link`, `scan_attachment`).

## Rules

1. **Only touch chosen sources.** Ask the user which connected apps to check (for example "Gmail only") if they have not said. Never read from any other connected app.
2. **Read-only.** Never click, open, visit, download-and-run, reply to, or delete anything. Never fetch a link from a message.
3. **Minimum data.** Pull only recent unread or user-specified messages. Do not summarize unrelated private content.

## Workflow

1. Fetch the messages from the chosen source only.
2. For each message call `scan_email` with sender, subject, text body, HTML body when available, and attachments as `{filename: base64}` when the connector exposes them. If attachments are unavailable, say so and scan any downloaded file with `scan_attachment`.
3. For a lone suspicious link call `scan_link`.
4. Write the answer in this shape:
   - **Verdict** (LIKELY SAFE / CAUTION / SUSPICIOUS / DANGEROUS) and the one-line reason
   - **What it is** (credential phishing, malware delivery, scam, or ordinary mail)
   - **Links**: which are risky and why, in plain words
   - **Files**: real file type (not just the name), what it appears to contain, and whether it can harm the device
   - **What to do next**
5. For many messages, give a short table first (sender, subject, verdict), then details only for CAUTION and worse.

## Honesty

The scan is static and heuristic. A LIKELY SAFE result is not a guarantee, and unknown files should still be treated carefully. Say so briefly when the stakes are high (payments, passwords, executables).

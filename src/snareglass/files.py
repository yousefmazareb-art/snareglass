"""Static attachment inspection. Files are only read as bytes, never opened or executed."""
from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile

from .models import FileReport, Finding
from .urls import extract_urls

MAX_BYTES = 25 * 1024 * 1024

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi", ".dll", ".jar", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".iso", ".img", ".reg", ".cpl",
    ".chm", ".apk", ".dmg", ".pkg", ".sh", ".appimage", ".msix", ".appx",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif"}
EXEC_KINDS = {"pe", "elf", "lnk", "script", "iso"}

SCRIPT_PATTERNS = [
    (r"(?i)powershell[^\n]{0,40}\s-(e|enc|encodedcommand)\b", "critical", "SCRIPT_PS_ENCODED", "Encoded PowerShell command (hides what it runs)."),
    (r"(?i)\b(invoke-expression|iex)\b", "high", "SCRIPT_IEX", "Runs text as code (Invoke-Expression)."),
    (r"(?i)(downloadstring|downloadfile|invoke-webrequest|urlcache|bitsadmin)", "high", "SCRIPT_DOWNLOADER", "Downloads additional content from the internet."),
    (r"(?i)frombase64string|atob\(", "medium", "SCRIPT_BASE64", "Decodes hidden base64 data."),
    (r"(?i)(mshta|wscript\.shell|cscript|regsvr32|rundll32)", "high", "SCRIPT_LOLBIN", "Uses built-in Windows tools often abused to launch malware."),
    (r"(?i)\beval\s*\(|unescape\s*\(|fromcharcode", "medium", "SCRIPT_OBFUSCATION", "Uses eval/unescape/charCode tricks typical of obfuscated scripts."),
    (r"(?i)(curl|wget)[^\n]{0,80}\|\s*(ba)?sh", "critical", "SCRIPT_PIPE_SHELL", "Pipes a download straight into a shell."),
]


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect(data: bytes) -> tuple[str, str]:
    h = data[:32]
    if h[:2] == b"MZ":
        return "pe", "Windows program (EXE/DLL)"
    if h[:4] == b"\x7fELF":
        return "elf", "Linux program (ELF)"
    if h[:4] == b"%PDF":
        return "pdf", "PDF document"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole", "Legacy Microsoft Office file (DOC/XLS/PPT)"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip", "ZIP-based file"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive", "7-Zip archive"
    if h[:4] == b"Rar!":
        return "archive", "RAR archive"
    if h[:2] == b"\x1f\x8b":
        return "archive", "GZIP archive"
    if h[:4] == b"L\x00\x00\x00" and h[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
        return "lnk", "Windows shortcut (LNK)"
    if data[0x8001:0x8006] == b"CD001":
        return "iso", "Disk image (ISO)"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "image", "PNG image"
    if h[:3] == b"\xff\xd8\xff":
        return "image", "JPEG image"
    if h[:4] == b"GIF8":
        return "image", "GIF image"
    sample = data[:4096]
    try:
        text = sample.decode("utf-8")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(len(text), 1)
        if printable > 0.95:
            low = text.lower()
            if "<html" in low or "<!doctype html" in low or "<script" in low or "<form" in low:
                return "html", "HTML page"
            if text.startswith("#!") or re.search(r"(?i)powershell|wscript|@echo off|\bcmd /c\b|function\s+\w+\s*\(", text):
                return "script", "Script"
            return "text", "Plain text"
    except UnicodeDecodeError:
        pass
    return "binary", "Unknown binary data"


def _collapse(s: str, n: int = 300) -> str:
    return re.sub(r"\s+", " ", s).strip()[:n]


def _scan_text(text: str, rep: FileReport) -> None:
    for pat, sev, code, detail in SCRIPT_PATTERNS:
        if re.search(pat, text):
            rep.findings.append(Finding(sev, code, detail))
    rep.urls += extract_urls(text)[:25]


def _analyze_zip(data: bytes, ext: str, rep: FileReport) -> None:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        rep.findings.append(Finding("medium", "ZIP_CORRUPT", "File looks like a ZIP but is damaged or malformed."))
        return
    names = z.namelist()
    infos = z.infolist()
    total = sum(i.file_size for i in infos)
    if total > 200 * 1024 * 1024 and total > 100 * max(len(data), 1):
        rep.findings.append(Finding("high", "ZIP_BOMB", "Archive expands to a huge size (possible zip bomb)."))
    if any(i.flag_bits & 1 for i in infos):
        rep.findings.append(Finding("medium", "ZIP_ENCRYPTED", "Archive is password-protected, which hides contents from antivirus scanners."))

    if any(n.startswith("word/") for n in names):
        rep.detected_type, rep.description = "docx", "Word document (OOXML)"
        try:
            xml = z.read("word/document.xml").decode("utf8", "ignore")
            rep.preview = _collapse(re.sub(r"<[^>]+>", " ", xml))
        except KeyError:
            pass
    elif any(n.startswith("xl/") for n in names):
        rep.detected_type, rep.description = "xlsx", "Excel workbook (OOXML)"
    elif any(n.startswith("ppt/") for n in names):
        rep.detected_type, rep.description = "pptx", "PowerPoint file (OOXML)"
    elif "AndroidManifest.xml" in names:
        rep.detected_type, rep.description = "apk", "Android app package (APK)"
        rep.findings.append(Finding("high", "APK_FILE", "Android app installer sent as an attachment."))
    elif any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names:
        rep.detected_type, rep.description = "jar", "Java archive (JAR)"
        rep.findings.append(Finding("high", "JAR_FILE", "Java program archive; can run code if opened."))
    else:
        rep.detected_type = "zip"
        rep.description = f"ZIP archive with {len(names)} item(s)"
        rep.preview = ", ".join(names[:12])

    lower = [n.lower() for n in names]
    if any("vbaproject.bin" in n for n in lower):
        rep.findings.append(Finding("high", "OFFICE_MACROS", "Contains VBA macros, the most common way Office files deliver malware."))
    if any("/embeddings/" in n or "oleobject" in n for n in lower):
        rep.findings.append(Finding("medium", "OFFICE_EMBEDDED", "Contains embedded objects/files."))
    for n in names:
        if n.endswith(".rels"):
            try:
                rel = z.read(n).decode("utf8", "ignore")
            except Exception:
                continue
            if re.search(r'TargetMode="External"', rel) and re.search(r'attachedTemplate|oleObject|frame', rel, re.I):
                rep.findings.append(Finding("high", "OFFICE_REMOTE_TEMPLATE", "Document loads content from a remote server when opened."))
                break
    inner = [n for n in lower if os.path.splitext(n)[1] in DANGEROUS_EXT]
    if inner and rep.detected_type in {"zip"}:
        rep.findings.append(Finding("high", "ZIP_CONTAINS_EXECUTABLE", f"Archive contains runnable file(s): {', '.join(inner[:5])}."))


def _analyze_pdf(data: bytes, rep: FileReport) -> None:
    low = data.lower()
    pages = len(re.findall(rb"/type\s*/page[^s]", low))
    uris = re.findall(rb"/uri\s*\(([^)]{1,200})\)", data, re.I)
    rep.preview = f"{pages} page(s), {len(uris)} link(s)"
    rep.urls += [u.decode("latin1") for u in uris[:25]]
    for tok, sev, code, detail in [
        (b"/javascript", "high", "PDF_JAVASCRIPT", "PDF contains JavaScript."),
        (b"/js", "medium", "PDF_JS", "PDF contains a JS action."),
        (b"/openaction", "medium", "PDF_OPENACTION", "PDF runs an action automatically when opened."),
        (b"/launch", "high", "PDF_LAUNCH", "PDF can launch an external program."),
        (b"/embeddedfile", "medium", "PDF_EMBEDDED", "PDF hides an embedded file."),
    ]:
        if tok in low:
            rep.findings.append(Finding(sev, code, detail))
    if pages and pages <= 1 and uris:
        rep.findings.append(Finding("low", "PDF_LINK_ONLY", "One-page PDF that mainly exists to carry a link (common phishing lure)."))


def analyze_file(name: str, data: bytes) -> FileReport:
    truncated = len(data) > MAX_BYTES
    data = data[:MAX_BYTES]
    kind, desc = detect(data)
    rep = FileReport(name=name, size=len(data), sha256=_hash(data), detected_type=kind, description=desc)
    ext = os.path.splitext(name.lower())[1]

    if truncated:
        rep.findings.append(Finding("info", "FILE_TRUNCATED", f"Only the first {MAX_BYTES // (1024 * 1024)} MB were inspected."))
    if ext in DANGEROUS_EXT:
        rep.findings.append(Finding("high", "EXT_DANGEROUS", f"'{ext}' files can run code on your device."))
    if ext in MACRO_EXT:
        rep.findings.append(Finding("high", "EXT_MACRO", f"'{ext}' is a macro-enabled Office format."))
    if re.search(r"(?i)\.(pdf|docx?|xlsx?|jpe?g|png|txt)\s*\.(exe|scr|js|vbs|bat|cmd|lnk|hta|ps1)$", name) or re.search(r"[\u202e]", name):
        rep.findings.append(Finding("critical", "EXT_DOUBLE", "Filename disguises an executable as a document (double extension or hidden characters)."))
    if ext in DOC_EXT and kind in EXEC_KINDS:
        rep.findings.append(Finding("critical", "TYPE_MISMATCH", f"Named '{ext}' but the content is actually: {desc}."))
    if kind in {"pe", "elf"}:
        rep.findings.append(Finding("high", "FILE_EXECUTABLE", "Contents are a native program."))
    if kind == "lnk":
        rep.findings.append(Finding("high", "FILE_SHORTCUT", "Windows shortcuts can silently run commands."))
    if kind == "iso":
        rep.findings.append(Finding("medium", "FILE_DISK_IMAGE", "Disk images are used to bypass download warnings."))

    if kind == "zip":
        _analyze_zip(data, ext, rep)
    elif kind == "pdf":
        _analyze_pdf(data, rep)
    elif kind == "ole":
        if b"VBA" in data or b"_VBA_PROJECT" in data or b"Macros" in data:
            rep.findings.append(Finding("high", "OFFICE_MACROS", "Legacy Office file with VBA macros."))
    elif kind in {"html", "script", "text"}:
        text = data.decode("utf8", "ignore")
        rep.preview = _collapse(re.sub(r"<[^>]+>", " ", text) if kind == "html" else text)
        _scan_text(text, rep)
        if kind == "html":
            if re.search(r"(?i)type\s*=\s*[\"']?password", text):
                rep.findings.append(Finding("high", "HTML_PASSWORD_FORM", "HTML attachment contains a password box (offline credential-harvesting page)."))
            if re.search(r"(?i)<form[^>]+action\s*=\s*[\"']?https?://", text):
                rep.findings.append(Finding("high", "HTML_FORM_EXTERNAL", "Form submits data to an external website."))
        if kind == "script":
            rep.findings.append(Finding("medium", "FILE_SCRIPT", "Script file that could run commands."))
    if not rep.preview:
        rep.preview = f"{len(data):,} bytes"
    return rep

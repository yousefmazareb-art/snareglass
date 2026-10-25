from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 60}


@dataclass
class Finding:
    severity: str  # info | low | medium | high | critical
    code: str
    detail: str

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


@dataclass
class UrlReport:
    url: str
    host: str = ""
    findings: list[Finding] = field(default_factory=list)


@dataclass
class FileReport:
    name: str
    size: int
    sha256: str
    detected_type: str
    description: str
    preview: str = ""
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


@dataclass
class Report:
    sender: str = ""
    subject: str = ""
    findings: list[Finding] = field(default_factory=list)
    urls: list[UrlReport] = field(default_factory=list)
    files: list[FileReport] = field(default_factory=list)
    score: int = 0
    verdict: str = "LIKELY SAFE"
    categories: list[str] = field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        out = list(self.findings)
        for u in self.urls:
            out += u.findings
        for f in self.files:
            out += f.findings
        return out

    def to_dict(self) -> dict:
        return asdict(self)

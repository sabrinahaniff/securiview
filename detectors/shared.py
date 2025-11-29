from typing import Optional
from models import VulnerabilityFinding, FindingType, SeverityType


def _build_finding(
    *,
    id: int,
    type: FindingType,
    severity: SeverityType,
    description: str,
    line: Optional[int] = None,
    snippet: Optional[str] = None,
    recommendation: Optional[str] = None,
    rule_id: Optional[str] = None,
    owasp: Optional[str] = None,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=id,
        type=type,
        severity=severity,
        description=description,
        line=line,
        snippet=snippet,
        recommendation=recommendation,
        rule_id=rule_id,
        owasp=owasp,
    )


def make_finding(
    *,
    id: int,
    type: FindingType,
    severity: SeverityType,
    description: str,
    line: Optional[int] = None,
    snippet: Optional[str] = None,
    recommendation: Optional[str] = None,
    rule_id: Optional[str] = None,
    owasp: Optional[str] = None,
) -> VulnerabilityFinding:
    return _build_finding(
        id=id,
        type=type,
        severity=severity,
        description=description,
        line=line,
        snippet=snippet,
        recommendation=recommendation,
        rule_id=rule_id,
        owasp=owasp,
    )

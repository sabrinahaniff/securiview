from typing import Literal, Optional
from models import VulnerabilityFinding


def new_finding(
    id_value: int,
    vtype: Literal["SQL_INJECTION", "XSS", "SECRET"],
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    description: str,
    line: Optional[int] = None,
    snippet: Optional[str] = None,
    recommendation: Optional[str] = None,
) -> VulnerabilityFinding:
    """Small helper so all findings are created the same way."""
    return VulnerabilityFinding(
        id=id_value,
        type=vtype,
        severity=severity,
        description=description,
        line=line,
        snippet=snippet,
        recommendation=recommendation,
    )

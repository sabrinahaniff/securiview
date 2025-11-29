from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


_REDIRECT_SINKS = [
    r"\bredirect\s*\(",
    r"\bHttpResponseRedirect\s*\(",
    r"\bResponse\.redirect\s*\(",
    r"window\.location\s*=",
    r"location\.href\s*=",
]

_USER_INPUT_HINTS = [
    r"request\.args",
    r"request\.GET",
    r"request\.query_params",
    r"req\.query",
    r"req\.params",
    r"Request\.QueryString",
]


def detect_open_redirect(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    sink_re = re.compile("|".join(_REDIRECT_SINKS))
    user_re = re.compile("|".join(_USER_INPUT_HINTS))

    current_id = start_id

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not sink_re.search(line):
            continue

        if not user_re.search(line):
            continue

        description = (
            "Possible open redirect: redirect/URL is derived from user-controlled input. "
            "Attackers can use this to send users to malicious sites while appearing to "
            "come from your domain."
        )
        recommendation = (
            "Use a whitelist of allowed redirect targets or map short codes to known URLs. "
            "Never redirect directly to arbitrary user-provided URLs."
        )

        findings.append(
            make_finding(
                id=current_id,
                type="OPEN_REDIRECT",
                severity="MEDIUM",
                description=description,
                line=idx,
                snippet=line,
                recommendation=recommendation,
            )
        )
        current_id += 1

    return findings

from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


# Very simple secret/credential patterns.
# These are intentionally broad heuristics.
_SECRET_PATTERNS = [
    # AWS-style access key IDs
    r"AKIA[0-9A-Z]{16}",
    # Generic 'secret' / 'password' assignments
    r"(secret|password|passwd|api_key|token)\s*=\s*[\"'][^\"']+[\"']",
    # Bearer tokens or long-looking tokens in headers
    r"Authorization\s*[:=]\s*[\"']Bearer [^\"']+[\"']",
]


def detect_secrets(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    secret_re = re.compile("|".join(_SECRET_PATTERNS))

    current_id = start_id

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if not line:
            continue

        if secret_re.search(line):
            description = (
                "Possible hardcoded secret detected (API key, password, token, or credential). "
                "If this code is committed or shared, the secret can be abused by attackers."
            )
            recommendation = (
                "Move secrets into environment variables, a secrets manager, or configuration "
                "files excluded from version control. Rotate or revoke this secret immediately "
                "if it has already been committed."
            )

            findings.append(
                make_finding(
                    id=current_id,
                    type="SECRET",
                    severity="HIGH",
                    description=description,
                    line=idx,
                    snippet=line.strip(),
                    recommendation=recommendation,
                    owasp="OWASP A02: Cryptographic Failures",
                )
            )
            current_id += 1

    return findings

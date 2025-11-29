from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


_SECRET_PAT = r"jwt_secret\s*=\s*[\"'][^\"']+[\"']"
_DECODE_NO_VERIFY = r"jwt\.decode\([^)]*verify\s*=\s*False"
_DECODE_GENERIC = r"jwt\.decode\s*\("


def detect_jwt_issues(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    secret_re = re.compile(_SECRET_PAT)
    no_verify_re = re.compile(_DECODE_NO_VERIFY)
    decode_re = re.compile(_DECODE_GENERIC)

    current_id = start_id

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()

        if secret_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="JWT",
                    severity="MEDIUM",
                    description="Hardcoded JWT secret detected in source code.",
                    line=idx,
                    snippet=line,
                    recommendation="Move JWT secrets into environment variables or a secrets manager.",
                    owasp="OWASP A07: Identification & Auth Failures",
                )
            )
            current_id += 1
            continue

        if no_verify_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="JWT",
                    severity="CRITICAL",
                    description="JWT decode with verify=False; tokens will not be validated.",
                    line=idx,
                    snippet=line,
                    recommendation="Enable signature and claim verification when decoding JWTs.",
                    owasp="OWASP A07: Identification & Auth Failures",
                )
            )
            current_id += 1
            continue

        # Generic decode: we could add a low-severity nudge
        if decode_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="JWT",
                    severity="LOW",
                    description="JWT decoding detected; ensure you validate signature, issuer, audience, and expiration.",
                    line=idx,
                    snippet=line,
                    recommendation="Verify iss/aud/exp and signature when decoding JWTs.",
                    owasp="OWASP A07: Identification & Auth Failures",
                )
            )
            current_id += 1

    return findings

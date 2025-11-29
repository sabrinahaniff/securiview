import re
from typing import List, Optional
from models import VulnerabilityFinding
from detectors.shared import new_finding


# Each entry: (pattern, description, recommendation, severity)
SECRET_PATTERNS = [
    (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key ID detected in code.",
        "Remove AWS keys from source code. Use environment variables or a secrets manager (e.g., AWS Secrets Manager). "
        "Rotate this credential immediately.",
        "CRITICAL",
    ),
    (
        r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "Private key material detected in code.",
        "Never commit private keys into repositories. Store them in a secure key store or secrets manager and rotate this key.",
        "CRITICAL",
    ),
    (
        r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"\n]+['\"]",
        "Hardcoded API key detected.",
        "Move API keys to environment variables or a secrets manager. Regenerate this key if it may have leaked.",
        "HIGH",
    ),
    (
        r"(?i)secret[_-]?key\s*[:=]\s*['\"][^'\"\n]+['\"]",
        "Hardcoded secret key detected.",
        "Do not hardcode secret keys. Use environment variables or a secrets manager and rotate this secret.",
        "HIGH",
    ),
    (
        r"(?i)password\s*[:=]\s*['\"][^'\"\n]+['\"]",
        "Hardcoded password detected.",
        "Do not store passwords in code. Use environment variables, a config file outside version control, or a secrets manager. "
        "Change this password if it has been pushed to a repo.",
        "HIGH",
    ),
    (
        r"(?i)token\s*[:=]\s*['\"][^'\"\n]+['\"]",
        "Hardcoded token detected.",
        "Avoid hardcoding access tokens. Store them in a secure secrets manager and rotate this token.",
        "HIGH",
    ),
]


# optional generic high-entropy token (can be noisy, so MEDIUM)
GENERIC_TOKEN_PATTERN = (
    r"['\"][A-Za-z0-9_\-]{32,}['\"]",  # long random-looking string
    "Potential secret/token: long random-looking string literal.",
    "Verify whether this value is a credential or token. If so, move it to a secure storage mechanism "
    "and rotate it.",
    "MEDIUM",
)


def detect_secrets(
    code: str,
    language: Optional[str] = None,
    start_id: int = 0,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()
    next_id = start_id

    # specific patterns
    for line_no, line in enumerate(lines, start=1):
        for pattern, desc, rec, severity in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    new_finding(
                        id_value=next_id,
                        vtype="SECRET",
                        severity=severity,  # type: ignore[arg-type]
                        description=desc,
                        line=line_no,
                        snippet=line.strip(),
                        recommendation=rec,
                    )
                )
                next_id += 1
                # a line could contain multiple secrets so no break

        # generic long token
        pattern, desc, rec, severity = GENERIC_TOKEN_PATTERN
        if re.search(pattern, line):
            findings.append(
                new_finding(
                    id_value=next_id,
                    vtype="SECRET",
                    severity=severity,  # type: ignore[arg-type]
                    description=desc,
                    line=line_no,
                    snippet=line.strip(),
                    recommendation=rec,
                )
            )
            next_id += 1

    return findings

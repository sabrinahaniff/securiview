from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


_WEAK_HASHES = [
    r"\bmd5\b",
    r"\bMD5\b",
    r"\bsha1\b",
    r"\bSHA1\b",
]

_ECB_HINTS = [
    r"MODE_ECB",
    r"\bECB\b",
]

_STATIC_IV_HINT = r"\b(iv|IV)\s*=\s*[\"']?[0-9a-fA-F]{8,}[\"']?"


def detect_crypto_issues(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    weak_hash_re = re.compile("|".join(_WEAK_HASHES))
    ecb_re = re.compile("|".join(_ECB_HINTS))  # <- keep your existing var name here if different
    # 🔧 use the defined constant here
    iv_re = re.compile(_STATIC_IV_HINT)

    current_id = start_id

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()

        if weak_hash_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="CRYPTO",
                    severity="MEDIUM",
                    description="Use of weak hash function (MD5/SHA1) detected.",
                    line=idx,
                    snippet=line,
                    recommendation="Use a modern hash function (SHA-256, SHA-3, bcrypt, Argon2, PBKDF2) instead.",
                    owasp="OWASP A02: Cryptographic Failures",
                )
            )
            current_id += 1
            continue

        if ecb_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="CRYPTO",
                    severity="HIGH",
                    description="Block cipher used in ECB mode; this leaks structure and is considered insecure.",
                    line=idx,
                    snippet=line,
                    recommendation="Use a secure mode (GCM, CBC with random IV, or ChaCha20-Poly1305) instead of ECB.",
                    owasp="OWASP A02: Cryptographic Failures",
                )
            )
            current_id += 1
            continue

        if iv_re.search(line):
            findings.append(
                make_finding(
                    id=current_id,
                    type="CRYPTO",
                    severity="MEDIUM",
                    description="Possible hardcoded IV detected in crypto code.",
                    line=idx,
                    snippet=line,
                    recommendation="Use a random IV generated at runtime and never reuse IVs for the same key.",
                    owasp="OWASP A02: Cryptographic Failures",
                )
            )
            current_id += 1

    return findings

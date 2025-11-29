from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


# Very simple heuristics: user-controlled or raw variables in file paths
_PATH_FUNCS = [
    r"\bopen\s*\(",
    r"\bos\.open\s*\(",
    r"\bsend_file\s*\(",
    r"\bsend_from_directory\s*\(",
    r"\bFile\(",
]

_USER_INPUT_HINTS = [
    r"request\.args\[?",
    r"request\.GET",
    r"request\.POST",
    r"req\.body",
    r"req\.params",
    r"req\.query",
    r"input\(",
    r"sys\.argv",
]


def detect_path_traversal(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    path_re = re.compile("|".join(_PATH_FUNCS))
    user_re = re.compile("|".join(_USER_INPUT_HINTS))
    dotdot_re = re.compile(r"\.\./")

    current_id = start_id

    for idx, line in enumerate(lines, start=1):
        if not path_re.search(line):
            continue

        # If we see any trace of user input OR explicit "../" patterns
        if user_re.search(line) or dotdot_re.search(line):
            description = (
                "Possible path traversal / insecure file access. File paths may include "
                "user-controlled input or traversal sequences (../)."
            )
            recommendation = (
                "Normalize and validate file paths before use. Reject any path containing "
                "traversal sequences (../) and restrict access to a known base directory."
            )

            findings.append(
                make_finding(
                    id=current_id,
                    type="PATH_TRAVERSAL",
                    severity="HIGH",
                    description=description,
                    line=idx,
                    snippet=line.strip(),
                    recommendation=recommendation,
                    owasp="OWASP A01: Broken Access Control",
                )
            )
            current_id += 1

    return findings

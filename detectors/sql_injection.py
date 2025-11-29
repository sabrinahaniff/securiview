import re
from typing import List, Optional

from models import VulnerabilityFinding
from detectors.shared import make_finding


# Very simple patterns to start with.
# These are *heuristics*, not perfect.
SQLI_SUSPICIOUS_PATTERNS = [
    # "SELECT ... " + user_input   (string concatenation near SQL)
    r"(SELECT|INSERT|UPDATE|DELETE).*(\"|').*\+.*",
    # ' OR 1=1 style patterns
    r"(['\"]) *OR *1 *= *1",
    # SQL comment marker (often used to chop off rest of query)
    r"--",
    # Explicit DROP TABLE
    r"; *DROP +TABLE",
]


def detect_sql_injection(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    current_id = start_id

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        for pattern in SQLI_SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                desc = (
                    "Possible SQL injection pattern: dynamic SQL construction or suspicious SQL fragment. "
                    "User input may be concatenated into a query instead of being parameterized."
                )
                rec = (
                    "Use parameterized queries / prepared statements instead of building SQL strings with "
                    "user input. For example, use placeholders (?, $1, :name) and pass values separately."
                )

                findings.append(
                    make_finding(
                        id=current_id,
                        type="SQL_INJECTION",
                        severity="HIGH",
                        description=desc,
                        line=idx,
                        snippet=line,
                        recommendation=rec,
                        owasp="OWASP A03: Injection",
                    )
                )

                current_id += 1
                # Avoid duplicating the same line for multiple patterns
                break

    return findings

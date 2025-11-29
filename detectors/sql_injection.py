import re
from typing import List, Optional
from models import VulnerabilityFinding
from detectors.shared import new_finding


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
    start_id: int = 0,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    next_id = start_id

    for line_no, line in enumerate(lines, start=1):
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
                    new_finding(
                        id_value=next_id,
                        vtype="SQL_INJECTION",
                        severity="HIGH",
                        description=desc,
                        line=line_no,
                        snippet=line.strip(),
                        recommendation=rec,
                    )
                )
                next_id += 1
                # Avoid duplicating the same line for multiple patterns
                break

    return findings

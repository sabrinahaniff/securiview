import re
from typing import List, Optional
from models import VulnerabilityFinding
from detectors.shared import new_finding


# dangerous JavaScript sinks
XSS_SINK_PATTERNS = [
    r"innerHTML\s*=",
    r"document\.write\s*\(",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
]

# HTML construction using string concatenation
HTML_BUILD_PATTERNS = [
    r"<\w+>.*\+.*</\w+>",             # e.g. "<div>" + userInput + "</div>"
    r"(<script>).*",                  # script tags
    r"on\w+\s*=",                     # inline event handlers: onclick=...
    r"`.*\$\{.*\}.*`",                # template literal interpolation: `${var}`
]


def detect_xss(
    code: str,
    language: Optional[str] = None,
    start_id: int = 0
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()
    next_id = start_id

    for line_no, line in enumerate(lines, start=1):
        # check JS sinks
        for pattern in XSS_SINK_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                desc = (
                    "Potential XSS vulnerability: unsafe use of DOM sink (e.g., innerHTML, document.write). "
                    "If user input flows here, arbitrary script execution is possible."
                )
                rec = (
                    "Avoid assigning untrusted input into HTML sinks. "
                    "Use textContent instead, or sanitize/escape the input with a trusted library."
                )
                findings.append(
                    new_finding(
                        id_value=next_id,
                        vtype="XSS",
                        severity="HIGH",
                        description=desc,
                        line=line_no,
                        snippet=line.strip(),
                        recommendation=rec,
                    )
                )
                next_id += 1
                break

        # check HTML building
        for pattern in HTML_BUILD_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                desc = (
                    "Possible XSS pattern: raw HTML construction with unescaped variables. "
                    "If user-controlled data is inserted into HTML, attacker-controlled script can execute."
                )
                rec = (
                    "Do not construct HTML with string concatenation. "
                    "Use safe templating engines, escape dynamic content, or sanitize inputs."
                )
                findings.append(
                    new_finding(
                        id_value=next_id,
                        vtype="XSS",
                        severity="MEDIUM",
                        description=desc,
                        line=line_no,
                        snippet=line.strip(),
                        recommendation=rec,
                    )
                )
                next_id += 1
                break

    return findings

import re
from typing import List, Optional

from .shared import make_finding
from models import VulnerabilityFinding


# DOM sinks where HTML can execute
DOM_SINK_PATTERN = re.compile(
    r"\b(innerHTML|outerHTML|document\.write(?:ln)?)\b"
)

# Raw HTML string concatenation, e.g. "<p>" + comment + "</p>"
HTML_CONCAT_PATTERN = re.compile(
    r'["\']<[^"\']*["\']\s*\+\s*[A-Za-z_][A-Za-z0-9_]*'
)

# Template literals with HTML + interpolation, e.g. `<p>${comment}</p>`
TEMPLATE_HTML_PATTERN = re.compile(
    r"`[^`]*<[^`>]*\$\{[^`]*\}[^`]*`"
)


def detect_xss(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    """
    Heuristic XSS detector.

    - Only looks at:
        * DOM sinks: innerHTML / outerHTML / document.write
        * Raw HTML construction with variables
    - Explicitly treats .textContent as SAFE.
    - Does not flag random string assignments (fixes ENVIRONMENT example).
    """
    findings: List[VulnerabilityFinding] = []
    lines = code.splitlines()

    next_id = start_id

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        # 1) Explicitly treat textContent as safe
        #    p.textContent = comment;  --> DO NOT flag
        if "textContent" in line:
            continue

        # 2) DOM sink usage: innerHTML / outerHTML / document.write
        if DOM_SINK_PATTERN.search(line):
            # If assigning an empty literal, it's safe-ish:
            # element.innerHTML = "";
            if re.search(r'=\s*["\']\s*["\']\s*;?$', line):
                continue

            description = (
                "Potential XSS vulnerability: unsafe use of DOM sink "
                "(e.g., innerHTML, outerHTML, document.write). "
                "If user input flows here, arbitrary script execution is possible."
            )
            recommendation = (
                "Avoid assigning untrusted input into HTML sinks. "
                "Use textContent instead, or sanitize/escape the input with a trusted library."
            )

            findings.append(
                make_finding(
                    id=next_id,
                    type="XSS",
                    severity="HIGH",
                    description=description,
                    line=lineno,
                    snippet=line,
                    recommendation=recommendation,
                    owasp="OWASP A03: Injection",
                )
            )
            next_id += 1
            # continue, we don't want to double-count the same line
            continue

        # 3) Raw HTML construction with variables (string concat or template literals)
        if HTML_CONCAT_PATTERN.search(line) or TEMPLATE_HTML_PATTERN.search(line):
            description = (
                "Possible XSS pattern: raw HTML construction with unescaped variables. "
                "If user-controlled data is inserted into HTML, attacker-controlled script can execute."
            )
            recommendation = (
                "Do not construct HTML with string concatenation. "
                "Use safe templating engines, escape dynamic content, or sanitize inputs."
            )

            findings.append(
                make_finding(
                    id=next_id,
                    type="XSS",
                    severity="MEDIUM",
                    description=description,
                    line=lineno,
                    snippet=line,
                    recommendation=recommendation,
                    owasp="OWASP A03: Injection",
                )
            )
            next_id += 1

    return findings

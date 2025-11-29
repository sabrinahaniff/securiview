from __future__ import annotations

from typing import List, Optional

from .shared import make_finding
from models import VulnerabilityFinding


DANGEROUS_FUNCS = [
    "eval(",
    "exec(",
    "Function(",               # JS: new Function(...)
    "vm.runInThisContext(",    # Node.js
    "ast.literal_eval(",       # Python (less bad, still worth flagging low/med)
]


def detect_dangerous_eval(
    code: str,
    language: Optional[str] = None,
    start_id: int = 1,
) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    next_id = start_id

    for lineno, raw_line in enumerate(code.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        for func in DANGEROUS_FUNCS:
            if func in line:
                snippet = line

                if "ast.literal_eval" in line:
                    severity = "MEDIUM"
                    description = (
                        "Use of ast.literal_eval. Safer than eval, but may still be risky "
                        "if given untrusted input."
                    )
                    recommendation = (
                        "Avoid evaluating untrusted strings as Python literals. "
                        "Prefer explicit parsing (e.g., json.loads) and validation."
                    )
                else:
                    severity = "HIGH"
                    description = (
                        "Potential code injection: dynamic evaluation of code via eval/exec-like API."
                    )
                    recommendation = (
                        "Avoid evaluating dynamically constructed code, especially if it includes "
                        "untrusted input. Use safer alternatives (parsers, explicit dispatch tables) "
                        "instead of eval/exec."
                    )

                findings.append(
                    make_finding(
                        id=next_id,
                        type="DANGEROUS_EVAL",
                        severity=severity,
                        description=description,
                        line=lineno,
                        snippet=snippet,
                        recommendation=recommendation,
                        owasp="OWASP A03: Injection",
                    )
                )
                next_id += 1
                break

    return findings

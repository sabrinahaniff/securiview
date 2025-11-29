from __future__ import annotations

from typing import List, Optional
import re

from .shared import make_finding
from models import VulnerabilityFinding


SHELL_FUNCS = [
    "os.system",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
    "Runtime.getRuntime().exec",      # Java
    "child_process.exec",             # Node
    "child_process.execFile",
]


def _looks_concatenated(command_expr: str) -> bool:
    """
    Try to spot obviously dynamic commands:
    - string + variable
    - template literals with ${}
    - format / f-strings with variables
    """
    if re.search(r'["\']\s*\+\s*\w+', command_expr):
        return True
    if re.search(r'\w+\s*\+\s*["\']', command_expr):
        return True
    if "${" in command_expr:  # JS template literal
        return True
    if "f\"" in command_expr or "f'" in command_expr:
        return True
    return False


def detect_command_injection(
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

        for func in SHELL_FUNCS:
            if func in line:
                snippet = line

                if _looks_concatenated(line):
                    severity = "HIGH"
                    description = (
                        "Possible command injection: shell command appears to be built "
                        "from variables or user-controlled input."
                    )
                    recommendation = (
                        "Avoid building shell commands with string concatenation. "
                        "Use parameterized APIs (e.g., subprocess.run([...], shell=False)) "
                        "and strongly validate or whitelist allowed commands/arguments."
                    )
                else:
                    severity = "MEDIUM"
                    description = (
                        "Use of shell execution function. If the command or its arguments "
                        "come from untrusted input, command injection may be possible."
                    )
                    recommendation = (
                        "Prefer safe, parameterized APIs (e.g., subprocess.run([...], shell=False)) "
                        "and avoid passing untrusted data into shell commands."
                    )

                findings.append(
                    make_finding(
                        id=next_id,
                        type="COMMAND_INJECTION",
                        severity=severity,
                        description=description,
                        line=lineno,
                        snippet=snippet,
                        recommendation=recommendation,
                        owasp="OWASP A03: Injection",
                    )
                )
                next_id += 1
                break  # avoid duplicate findings on same line

    return findings

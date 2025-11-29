from typing import List
from models import VulnerabilityFinding, AIExplanation


def explain_findings_with_ai(
    code: str,
    findings: List[VulnerabilityFinding],
) -> List[AIExplanation]:
    """
    For now, this is a simple rule-based explainer so the endpoint works
    even without a real LLM. Later, you can replace the guts with a Gemini call.
    """
    explanations: List[AIExplanation] = []

    for f in findings:
        if f.type == "SQL_INJECTION":
            explanation = (
                "This finding indicates that user-controlled data may be concatenated into an SQL query. "
                "If input is not validated or parameterized, an attacker can modify the query logic"
                " (e.g., using ' OR 1=1) to access or manipulate data."
            )
            fix = (
                "Switch to parameterized queries / prepared statements. "
                "In most frameworks this means using placeholders (?, $1, :name) and passing values separately "
                "from the query string."
            )
            scenario = (
                "An attacker submits crafted input like ' OR 1=1 -- to bypass authentication or dump entire tables."
            )

        elif f.type == "XSS":
            explanation = (
                "This finding suggests that untrusted data may be written into an HTML context (e.g., innerHTML, "
                "document.write, raw HTML strings). If that data contains HTML or JavaScript, it can execute "
                "in the victim's browser."
            )
            fix = (
                "Avoid writing raw HTML with concatenated strings. Use textContent or an escaping/sanitization "
                "library, or a templating engine that auto-escapes output."
            )
            scenario = (
                "A malicious user posts a comment containing <script> tags. When other users view the page, the "
                "script runs, stealing their cookies or performing actions on their behalf."
            )

        elif f.type == "SECRET":
            explanation = (
                "This finding indicates that a credential or secret value appears directly in source code. "
                "If the repository is leaked or improperly shared, attackers could reuse this credential."
            )
            fix = (
                "Move secrets into environment variables, a secrets manager, or a config file excluded from "
                "version control. Rotate/regenerate the exposed credential."
            )
            scenario = (
                "If this repository were made public, an attacker could use the hardcoded API key to access your "
                "cloud resources or third-party services and incur cost or data loss."
            )

        else:
            # Fallback for future types
            explanation = (
                "This is a potential security issue detected by a rule. Review the snippet and ensure that "
                "untrusted data is handled safely, and that no secrets or dangerous operations are exposed."
            )
            fix = "Review this code manually and apply least privilege, input validation, and secure defaults."
            scenario = None

        explanations.append(
            AIExplanation(
                finding_id=f.id,
                explanation=explanation,
                fix_suggestion=fix,
                attack_scenario=scenario,
            )
        )

    return explanations

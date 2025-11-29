from typing import List
from models import VulnerabilityFinding, AIExplanation


def explain_findings_with_ai(
    code: str,
    findings: List[VulnerabilityFinding],
) -> List[AIExplanation]:
    """
    Simple rule-based explainer so the /analyze/ai endpoint works
    even without a real LLM. Later you can swap this out for Gemini.
    """
    explanations: List[AIExplanation] = []

    for f in findings:
        # --- SQL injection ---
        if f.type == "SQL_INJECTION":
            explanation = (
                "This finding indicates that user-controlled data may be concatenated "
                "into an SQL query. If input is not validated or parameterized, an "
                "attacker can modify the query logic (for example using ' OR 1=1) to "
                "access or manipulate data."
            )
            fix = (
                "Switch to parameterized queries / prepared statements. Use placeholders "
                "like ?, $1, or :name and pass values separately from the query string. "
                "Also validate and constrain input where possible."
            )
            scenario = (
                "An attacker submits crafted input like ' OR 1=1 -- to bypass authentication "
                "on a login form and dump an entire users table."
            )

        # --- XSS ---
        elif f.type == "XSS":
            explanation = (
                "This finding suggests that untrusted data may be written into an HTML "
                "context (e.g., innerHTML, document.write, or raw HTML strings). If that "
                "data contains HTML or JavaScript, it can execute in the victim's browser."
            )
            fix = (
                "Avoid writing raw HTML with string concatenation. Use textContent or a "
                "templating engine that auto-escapes output, or sanitize/encode dynamic "
                "content with a trusted library."
            )
            scenario = (
                "A malicious user posts a comment containing <script> tags. When other users "
                "view the page, the script runs and steals their session cookies."
            )

        # --- Secrets in code ---
        elif f.type == "SECRET":
            explanation = (
                "This finding indicates that a credential or secret value appears directly "
                "in source code. If the repository is leaked or overly shared, attackers "
                "could reuse this credential."
            )
            fix = (
                "Move secrets into environment variables, a secrets manager, or a config "
                "file excluded from version control. Rotate or revoke the exposed secret."
            )
            scenario = (
                "If this repo were made public, an attacker could copy the hardcoded API key "
                "and use your third-party service or cloud account at your expense."
            )

        # --- Command injection ---
        elif f.type == "COMMAND_INJECTION":
            explanation = (
                "This finding points to code that executes shell commands. If any part of "
                "the command string comes from user-controlled input, an attacker may be "
                "able to run arbitrary system commands."
            )
            fix = (
                "Avoid building shell commands with string concatenation. Prefer parameterized "
                "APIs like subprocess.run([...], shell=False). Strictly validate or whitelist "
                "allowed commands and arguments."
            )
            scenario = (
                "An attacker passes input like '; rm -rf /' into a web parameter that is "
                "concatenated into an os.system() call, causing destructive commands to run."
            )

        # --- Dangerous eval / dynamic code ---
        elif f.type == "DANGEROUS_EVAL":
            explanation = (
                "This finding highlights dynamic evaluation of strings as code. If the evaluated "
                "string can be influenced by an attacker, they may be able to execute arbitrary "
                "code with the application's privileges."
            )
            fix = (
                "Remove eval/exec-style calls where possible. Replace them with explicit logic: "
                "dispatch tables, parsers, or configuration objects. Never evaluate untrusted "
                "data as code."
            )
            scenario = (
                "A web app calls eval() on a query parameter to compute a result. An attacker "
                "supplies a payload that reads environment variables or accesses internal services."
            )

        # --- Path traversal / file access ---
        elif f.type == "PATH_TRAVERSAL":
            explanation = (
                "This finding suggests that user input may influence file paths. Without proper "
                "validation, attackers could use sequences like '../' to escape the intended "
                "directory and read or overwrite arbitrary files."
            )
            fix = (
                "Normalize and validate paths. Enforce a fixed base directory and reject input "
                "containing path traversal sequences. Use safe file APIs that separate the concept "
                "of 'file identifier' from raw paths where possible."
            )
            scenario = (
                "An attacker requests '../../../etc/passwd' as a filename, and the server returns "
                "sensitive system files instead of only content from the public directory."
            )

        # --- Crypto issues ---
        elif f.type == "CRYPTO":
            explanation = (
                "This finding indicates a potential cryptographic weakness, such as use of "
                "outdated algorithms, insecure modes, or hardcoded keys and IVs."
            )
            fix = (
                "Use modern, well-reviewed cryptographic libraries with secure defaults. Avoid "
                "custom crypto. Follow current best practices for algorithm choice, key length, "
                "and key management."
            )
            scenario = (
                "An application uses ECB mode AES with a hardcoded key. An attacker who obtains "
                "ciphertexts can infer patterns and may eventually recover plaintext."
            )

        # --- JWT issues ---
        elif f.type == "JWT":
            explanation = (
                "This finding suggests a possible weakness in handling JSON Web Tokens, such as "
                "missing signature validation, insecure algorithms, or excessive token lifetimes."
            )
            fix = (
                "Ensure tokens are signed with a strong algorithm (e.g., HS256 or RS256) and that "
                "signatures are always verified. Enforce reasonable expiration times and validate "
                "audience and issuer claims."
            )
            scenario = (
                "If the application accepts unsigned tokens or 'none' as an algorithm, an attacker "
                "can forge their own token and impersonate other users."
            )

        # --- Open redirect ---
        elif f.type == "OPEN_REDIRECT":
            explanation = (
                "This finding indicates that unvalidated user input may control a redirect URL. "
                "Attackers can abuse this to send users through your site to a phishing or malware "
                "page while preserving trust in your domain."
            )
            fix = (
                "Whitelist allowed redirect targets or use opaque identifiers instead of raw URLs. "
                "Never redirect directly to arbitrary user-provided URLs."
            )
            scenario = (
                "A phishing email links to yourdomain.com/redirect?to=http://evil.example. The victim "
                "clicks a trusted domain and is silently forwarded to a malicious site."
            )

        # --- Fallback for anything new ---
        else:
            explanation = (
                "This is a potential security issue detected by a rule. Review the code and ensure "
                "that untrusted data is handled safely, secrets are protected, and dangerous operations "
                "are minimized and well-guarded."
            )
            fix = (
                "Review this code manually. Apply least privilege, input validation, output encoding, "
                "and secure defaults appropriate to the affected component."
            )
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

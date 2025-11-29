from .sql_injection import detect_sql_injection
from .xss import detect_xss
from .secrets import detect_secrets
from .command_injection import detect_command_injection
from .dangerous_eval import detect_dangerous_eval
from .path_traversal import detect_path_traversal
from .crypto import detect_crypto_issues
from .jwt import detect_jwt_issues
from .open_redirect import detect_open_redirect

__all__ = [
    "detect_sql_injection",
    "detect_xss",
    "detect_secrets",
    "detect_command_injection",
    "detect_dangerous_eval",
    "detect_path_traversal",
    "detect_crypto_issues",
    "detect_jwt_issues",
    "detect_open_redirect",
]

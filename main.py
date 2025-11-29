from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from models import (
    CodeAnalysisRequest,
    AnalysisResponse,
    AIAnalysisResponse,
    VulnerabilityFinding,
    AIExplanation,
)



from detectors.sql_injection import detect_sql_injection
from detectors.xss import detect_xss
from detectors.secrets import detect_secrets
from detectors.command_injection import detect_command_injection
from detectors.dangerous_eval import detect_dangerous_eval
from detectors.path_traversal import detect_path_traversal
from detectors.crypto import detect_crypto_issues
from detectors.jwt import detect_jwt_issues
from detectors.open_redirect import detect_open_redirect



from ai import explain_findings_with_ai


app = FastAPI(title="SecuriView", version="0.1.0")

# --- CORS (so the frontend can call the API) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only – tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Frontend serving ---
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"


@app.get("/", response_class=HTMLResponse)
async def serve_frontend() -> HTMLResponse:
    """Serve the static HTML UI."""
    index_file = FRONTEND_DIR / "index.html"
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


# --- Health check ---
@app.get("/health")
def health_check():
    return {"status": "ok"}


# --- Risk scoring ---
def compute_risk_score(findings: List[VulnerabilityFinding]) -> int:
    """Very simple risk aggregation: sum weights, cap at 100."""
    if not findings:
        return 0

    weights = {
        "LOW": 10,
        "MEDIUM": 25,
        "HIGH": 40,
        "CRITICAL": 60,
    }

    total = sum(weights.get(f.severity, 10) for f in findings)
    return min(100, total)


# --- Core analysis pipeline ---
def run_detectors(code: str, language: Optional[str] = None) -> AnalysisResponse:
    findings: List[VulnerabilityFinding] = []
    next_id = 1

    # SQL injection
    sqli = detect_sql_injection(code, language=language, start_id=next_id)
    findings.extend(sqli)
    next_id += len(sqli)

    # XSS
    xss = detect_xss(code, language=language, start_id=next_id)
    findings.extend(xss)
    next_id += len(xss)

    # Secrets
    secrets = detect_secrets(code, language=language, start_id=next_id)
    findings.extend(secrets)
    next_id += len(secrets)

    # Command injection
    cmd = detect_command_injection(code, language=language, start_id=next_id)
    findings.extend(cmd)
    next_id += len(cmd)

    # Dangerous eval / dynamic code
    dyn = detect_dangerous_eval(code, language=language, start_id=next_id)
    findings.extend(dyn)
    next_id += len(dyn)

    # Path traversal / file access
    paths = detect_path_traversal(code, language=language, start_id=next_id)
    findings.extend(paths)
    next_id += len(paths)

    # Crypto issues
    crypto = detect_crypto_issues(code, language=language, start_id=next_id)
    findings.extend(crypto)
    next_id += len(crypto)

    # JWT issues
    jwt_findings = detect_jwt_issues(code, language=language, start_id=next_id)
    findings.extend(jwt_findings)
    next_id += len(jwt_findings)

    # Open redirect
    redirects = detect_open_redirect(code, language=language, start_id=next_id)
    findings.extend(redirects)
    next_id += len(redirects)

    risk_score = compute_risk_score(findings)
    return AnalysisResponse(findings=findings, risk_score=risk_score)


#endpoints
@app.post("/analyze", response_model=AnalysisResponse)
def analyze_code(payload: CodeAnalysisRequest) -> AnalysisResponse:
    """Rule-based static analysis only."""
    return run_detectors(code=payload.code, language=payload.language)


@app.post("/analyze/ai", response_model=AIAnalysisResponse)
def analyze_code_with_ai(payload: CodeAnalysisRequest) -> AIAnalysisResponse:
    """
    Run static detectors, then generate higher-level explanations for each finding.
    Currently uses a rule-based explainer; later you can swap in a Gemini-backed version.
    """
    base = run_detectors(code=payload.code, language=payload.language)

    ai_explanations: List[AIExplanation] = explain_findings_with_ai(
        code=payload.code,
        findings=base.findings,
    )

    return AIAnalysisResponse(
        findings=base.findings,
        risk_score=base.risk_score,
        ai_explanations=ai_explanations,
    )

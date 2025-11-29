from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from models import (
    CodeAnalysisRequest,
    AnalysisResponse,
    VulnerabilityFinding,
    AIAnalysisResponse,
    AIExplanation,
)
from detectors.sql_injection import detect_sql_injection
from detectors.xss import detect_xss
from detectors.secrets import detect_secrets
from ai import explain_findings_with_ai


app = FastAPI(title="SecuriView", version="0.1.0")

# CORS so a frontend can call this later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev only – tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def index():
    """Serve the frontend UI."""
    html_path = Path("frontend/index.html")
    return html_path.read_text(encoding="utf-8")


@app.get("/health")
def health_check():
    return {"status": "ok"}


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


def run_detectors(code: str, language: Optional[str] = None) -> AnalysisResponse:
    findings: List[VulnerabilityFinding] = []
    next_id = 1

    # SQL injection detector
    sqli = detect_sql_injection(code, language=language, start_id=next_id)
    findings.extend(sqli)
    next_id += len(sqli)

    # XSS detector
    xss = detect_xss(code, language=language, start_id=next_id)
    findings.extend(xss)
    next_id += len(xss)

    # Secrets detector
    secrets = detect_secrets(code, language=language, start_id=next_id)
    findings.extend(secrets)
    next_id += len(secrets)

    risk_score = compute_risk_score(findings)
    return AnalysisResponse(findings=findings, risk_score=risk_score)


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

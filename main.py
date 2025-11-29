from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import CodeAnalysisRequest, AnalysisResponse, VulnerabilityFinding
from detectors.sql_injection import detect_sql_injection
from detectors.xss import detect_xss
from detectors.secrets import detect_secrets


app = FastAPI(title="SecuriView", version="0.1.0")

# CORS so a frontend can call this later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_code(payload: CodeAnalysisRequest) -> AnalysisResponse:
    code = payload.code
    language = payload.language

    findings: List[VulnerabilityFinding] = []
    next_id = 1

    #SQL injection detector
    sqli = detect_sql_injection(code, language=language, start_id=next_id)
    findings.extend(sqli)
    next_id += len(sqli)

    #XSS detector (stub)
    xss = detect_xss(code, language=language, start_id=next_id)
    findings.extend(xss)
    next_id += len(xss)

    #Secrets detector (stub)
    secrets = detect_secrets(code, language=language, start_id=next_id)
    findings.extend(secrets)
    next_id += len(secrets)

    risk_score = compute_risk_score(findings)

    return AnalysisResponse(findings=findings, risk_score=risk_score)


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

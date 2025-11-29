from typing import List, Optional, Literal
from pydantic import BaseModel

# All vulnerability types our detectors may emit
FindingType = Literal[
    "SQL_INJECTION",
    "XSS",
    "SECRET",
    "COMMAND_INJECTION",
    "DANGEROUS_EVAL",
    "PATH_TRAVERSAL",
    "CRYPTO",
    "JWT",
    "OPEN_REDIRECT",
]

SeverityType = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class VulnerabilityFinding(BaseModel):
    id: int
    type: FindingType
    severity: SeverityType
    description: str
    line: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None
    rule_id: Optional[str] = None

    # NEW: OWASP category label, e.g. "OWASP A03: Injection"
    owasp: Optional[str] = None


class AnalysisResponse(BaseModel):
    """Base response for /analyze (rule-based only)."""
    findings: List[VulnerabilityFinding]
    risk_score: int


class AIExplanation(BaseModel):
    finding_id: int
    explanation: str
    fix_suggestion: str
    attack_scenario: Optional[str] = None


class AIAnalysisResponse(AnalysisResponse):
    """Extended response for /analyze/ai with extra explanations."""
    ai_explanations: List[AIExplanation] = []


class CodeAnalysisRequest(BaseModel):
    code: str
    language: Optional[str] = None  # "python", "javascript", etc.
    mode: Optional[str] = None      # unused for now, but harmless

from typing import List, Literal, Optional
from pydantic import BaseModel


class CodeAnalysisRequest(BaseModel):
    """What the client sends us."""
    code: str
    language: Optional[str] = None  # "python", "javascript", "php"


class VulnerabilityFinding(BaseModel):
    """One detected issue in the code."""
    id: int
    type: Literal["SQL_INJECTION", "XSS", "SECRET"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    line: Optional[int] = None       # line number in the code (1-based)
    snippet: Optional[str] = None    # the code line or fragment
    recommendation: Optional[str] = None  # how to fix / improve


class AnalysisResponse(BaseModel):
    """Whole analysis result."""
    findings: List[VulnerabilityFinding]
    risk_score: int  # 0–100


class AIExplanation(BaseModel):
    """Extra AI context tied to a particular finding."""
    finding_id: int
    explanation: str          # high-level reasoning
    fix_suggestion: str       # how to fix it in practice
    attack_scenario: Optional[str] = None  # e.g. "An attacker could..."


class AIAnalysisResponse(AnalysisResponse):
    """Normal analysis + AI-generated explanations."""
    ai_explanations: List[AIExplanation]
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Any

@dataclass(frozen=True)
class AIRiskResult:
    score: float
    confidence: float
    model: str = 'external'
    factors: list[str] = field(default_factory=list)

class AIRiskProvider(Protocol):
    def assess(self, payload: Any, request: Any, evidence: dict[str, Any]) -> AIRiskResult: ...

@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    factors: list[str]
    deterministic_score: int = 0
    ai_score: float | None = None
    ai_confidence: float | None = None
    ai_model: str | None = None
    ai_factors: list[str] = field(default_factory=list)

def _level(score: float) -> str:
    return 'LOW' if score < 25 else 'MEDIUM' if score < 60 else 'HIGH' if score < 85 else 'CRITICAL'

def assess(payload, request, policy, advisory_reputation=None, ai_result: AIRiskResult | None = None):
    score=0; f=[]; amount=int(payload.amount)
    if policy.approval_threshold and amount>policy.approval_threshold: score+=25; f.append('above approval threshold')
    if policy.allowed_merchants and request.merchant not in policy.allowed_merchants: score+=40; f.append('untrusted merchant')
    if policy.allowed_networks and payload.network not in policy.allowed_networks: score+=40; f.append('untrusted network')
    if policy.allowed_assets and payload.asset not in policy.allowed_assets: score+=40; f.append('untrusted asset')
    if amount>policy.max_amount*.75: score+=15; f.append('high transaction amount')
    if advisory_reputation is not None and advisory_reputation<30: score+=20; f.append('low-confidence target reputation')
    elif advisory_reputation is not None and advisory_reputation<50: score+=10; f.append('elevated target reputation risk')
    deterministic=min(score,100)
    # AI is probabilistic evidence, never an authorization authority. Its contribution is bounded.
    final=float(deterministic)
    if ai_result is not None:
        ai_score=max(0,min(100,float(ai_result.score)))
        confidence=max(0,min(1,float(ai_result.confidence)))
        weight=max(0,min(1,float(getattr(policy,'ai_risk_weight',0.25))))
        bounded_ai=(ai_score-deterministic)*weight*confidence
        final=max(0,min(100,deterministic+bounded_ai))
        f.extend([f'ai:{x}' for x in ai_result.factors])
    return RiskResult(round(final),_level(final),f,deterministic,ai_result.score if ai_result else None,ai_result.confidence if ai_result else None,ai_result.model if ai_result else None,ai_result.factors if ai_result else [])

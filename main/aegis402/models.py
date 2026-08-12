from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "BLOCK"]


class PaymentRequirements(BaseModel):
    scheme: str = "exact"
    network: str = "base-sepolia"
    asset: str = "USDC"
    amount: str
    pay_to: str
    resource: str
    max_timeout_seconds: int = 300
    nonce: str | None = None


class PaymentPayload(BaseModel):
    payer: str
    resource: str
    amount: str
    pay_to: str
    nonce: str
    signature: str = "demo-signature"
    scheme: str = "exact"
    network: str = "base-sepolia"
    asset: str = "USDC"
    # EIP-3009-style authorization validity window, when the caller has one.
    # In a real "exact" EVM payload these two values are part of what the
    # payer cryptographically signed (validAfter / validBefore), so they
    # can be checked locally without calling out to the facilitator. When
    # they are absent (e.g. a scheme/network that doesn't use them) the
    # freshness guard falls back to server-side bookkeeping only -- see
    # freshness.check_payload_validity_window for the exact scope of that
    # guarantee.
    valid_after: int | None = None
    valid_before: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RequestContext(BaseModel):
    method: str
    path: str
    resource: str
    merchant: str
    request_id: str
    body_hash: str = ""
    headers_fingerprint: str = ""


class SecurityDecision(BaseModel):
    decision: Decision
    reason: str
    checks: dict[str, str]
    fingerprint: str
    event_id: str


class SettlementResult(BaseModel):
    success: bool
    tx_hash: str | None = None
    reason: str | None = None

    # Post-settlement facts, populated by the adapter from the facilitator's
    # actual SettlementResponse -- NOT re-derived from the client's payload.
    # The x402 v2 core SettlementResponse only guarantees success / errorReason
    # / transaction / network / payer (see specs/transports-v2/http.md). A
    # settled amount is NOT part of the core, interoperable response -- some
    # facilitator implementations include one (e.g. as an extra "amount"
    # field), most don't guarantee it. Treat settled_amount as best-effort.
    settled_network: str | None = None
    payer: str | None = None
    settled_amount: str | None = None

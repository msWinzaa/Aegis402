"""Context binding.

Ties the payment payload, the payment requirements the merchant actually
issued, and the concrete HTTP request together so a valid payment for one
resource/merchant/network/asset cannot be presented against a different
one ("cross-resource substitution").

Scope of the guarantee
-----------------------
This is a pre-filter on values the client/attacker controls in the request
it sends *to main*. It cannot detect a forged signature (that is the
facilitator's job via X402Adapter.verify) and it cannot detect that the
`asset`/`network` string itself is lying about which on-chain token
contract or chain actually moved funds -- that fact only becomes knowable
once the facilitator verifies/settles against the chain. Binding closes the
gap of "attacker reuses a real, validly-signed payment for resource A
against resource B", not "attacker forges a payment".
"""

from .models import PaymentPayload, PaymentRequirements, RequestContext
from .crypto import request_fingerprint, canonical_json


def check_context_binding(payload, requirements, request):
    if payload.resource != request.resource:
        return False, "resource mismatch"
    if requirements.resource != request.resource:
        return False, "payment requirement resource mismatch"
    if payload.resource != requirements.resource:
        return False, "payload/resource mismatch"
    if request.merchant != requirements.pay_to:
        return False, 'merchant/recipient mismatch'
    if payload.pay_to != requirements.pay_to:
        return False, "payTo mismatch"
    if payload.amount != requirements.amount:
        return False, "amount mismatch"
    if payload.scheme != requirements.scheme:
        return False, "scheme mismatch"
    if payload.network != requirements.network:
        return False, "network mismatch"
    if payload.asset != requirements.asset:
        return False, "asset mismatch"
    return True, "bound"


def binding_fingerprint(payload, requirements, request):
    return request_fingerprint(
        request.method,
        request.path,
        request.resource,
        payload.resource,
        payload.amount,
        payload.pay_to,
        payload.scheme,
        payload.network,
        payload.asset,
        requirements.resource,
        requirements.amount,
        requirements.pay_to,
        requirements.scheme,
        requirements.network,
        requirements.asset,
        request.body_hash,
        request.headers_fingerprint,
    )

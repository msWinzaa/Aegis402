import time

from aegis402.gateway import AegisGateway
from aegis402.models import PaymentPayload, PaymentRequirements, RequestContext
from aegis402.x402_adapter import MockX402Adapter


def base_case():
    resource = "https://demo.local/api/resource"
    req = PaymentRequirements(amount="1000", pay_to="merchant", resource=resource)
    payload = PaymentPayload(
        payer="agent",
        resource=resource,
        amount="1000",
        pay_to="merchant",
        nonce="n1",
    )
    ctx = RequestContext(
        method="GET",
        path="/api/resource",
        resource=resource,
        merchant="merchant",
        request_id="r1",
    )
    return payload, req, ctx


def test_cross_resource_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.resource = "https://demo.local/api/other"

    decision = AegisGateway(MockX402Adapter()).inspect(
        payload, req, ctx, time.time()
    )
    assert decision["decision"] == "BLOCK"


def test_normal_payment_is_allowed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    decision = AegisGateway(MockX402Adapter()).inspect(
        payload, req, ctx, time.time()
    )
    assert decision["decision"] == "ALLOW"

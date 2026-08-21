import time

from aegis402.gateway import AegisGateway
from aegis402.models import PaymentPayload, PaymentRequirements, RequestContext
from aegis402.x402_adapter import MockX402Adapter


def test_failed_settlement_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    resource = "https://demo.local/api/resource"
    req = PaymentRequirements(amount="1000", pay_to="merchant", resource=resource)
    payload = PaymentPayload(
        payer="agent",
        resource=resource,
        amount="1000",
        pay_to="merchant",
        nonce="settle-fail",
    )
    ctx = RequestContext(
        method="GET",
        path="/api/resource",
        resource=resource,
        merchant="merchant",
        request_id="r1",
    )

    gateway = AegisGateway(
        MockX402Adapter(settlement_should_fail=True)
    )
    decision = gateway.inspect(payload, req, ctx, time.time())

    assert decision["decision"] == "BLOCK"
    assert "settlement" in decision["reason"]

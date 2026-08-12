import json
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .atomicity import AtomicityGuard
from .gateway import AegisGateway
from .ledger import ThreatLedger
from .models import PaymentPayload, PaymentRequirements, RequestContext
from .policy import Policy
from .x402_adapter import MockX402Adapter, X402FacilitatorAdapter

app = FastAPI(title="main", version="0.1.1")

# Adapter selection. Defaults to the deterministic mock so the demo and
# `/docs` work with zero configuration. Set AEGIS402_ADAPTER=facilitator
# and AEGIS402_FACILITATOR_URL to exercise the real x402 SDK integration
# (see aegis402/x402_adapter.py::X402FacilitatorAdapter and SECURITY.md --
# this is still not a production-reviewed integration).
_adapter_kind = os.environ.get("AEGIS402_ADAPTER", "mock")
if _adapter_kind == "facilitator":
    _facilitator_url = os.environ.get("AEGIS402_FACILITATOR_URL", "https://x402.org/facilitator")
    adapter = X402FacilitatorAdapter(facilitator_url=_facilitator_url)
else:
    adapter = MockX402Adapter()

# Ledger and atomicity guard persist across requests/process lifetime so
# the demo's replay/ledger scenarios are meaningful across separate HTTP
# calls, not just within one. The adapter used per-request is NOT shared
# mutable state -- see make_case() -- so concurrent demo calls (e.g.
# /demo/race) don't race on adapter fields like settlement_should_fail.
ledger = ThreatLedger()
atomicity = AtomicityGuard()
policy = Policy()
gateway = AegisGateway(adapter=adapter, policy=policy, ledger=ledger, atomicity=atomicity)


class DemoRequest(BaseModel):
    attack: str = "normal"


def make_case(attack):
    resource = "https://demo.local/api/resource"

    requirements = PaymentRequirements(
        amount="1000",
        pay_to="merchant-demo",
        resource=resource,
        max_timeout_seconds=300,
    )

    payload = PaymentPayload(
        payer="agent-demo",
        resource=resource,
        amount="1000",
        pay_to="merchant-demo",
        nonce=f"nonce-{attack}-{uuid_suffix()}" if attack != "replay" else "nonce-replay-demo",
    )

    request = RequestContext(
        method="GET",
        path="/api/resource",
        resource=resource,
        merchant="merchant-demo",
        request_id="req-001",
    )

    issued_at = time.time()
    estimated_cost = 0
    case_adapter = MockX402Adapter()

    if attack == "cross-resource":
        payload.resource = "https://demo.local/api/other"
    elif attack == "expired":
        issued_at -= 1000
    elif attack == "invalid-signature":
        payload.signature = "invalid"
    elif attack == "cost":
        estimated_cost = 999_999
    elif attack == "settlement-failure":
        case_adapter.settlement_should_fail = True
    elif attack == "wrong-network":
        payload.network = "eip155:1"  # different chain than requirements
    elif attack == "expired-authorization":
        payload.valid_before = int(time.time()) - 60

    case_gateway = AegisGateway(
        adapter=case_adapter, policy=policy, ledger=ledger, atomicity=atomicity
    )

    return case_gateway, payload, requirements, request, issued_at, estimated_cost


def uuid_suffix():
    import uuid

    return uuid.uuid4().hex[:8]


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).resolve().parent.parent / "dashboard" / "index.html")


@app.get("/")
def root():
    return {
        "name": "main",
        "version": "0.1.1",
        "message": "Local security middleware prototype",
        "adapter": type(adapter).__name__,
        "docs": "/docs",
    }


@app.post("/demo/check")
def demo_check(body: DemoRequest):
    case_gateway, payload, requirements, request, issued_at, estimated_cost = make_case(
        body.attack
    )

    first = case_gateway.inspect(payload, requirements, request, issued_at, estimated_cost)

    second = None
    if body.attack == "replay":
        second = case_gateway.inspect(payload, requirements, request, issued_at, estimated_cost)

    return {
        "attack": body.attack,
        "first": first,
        "second": second,
    }


@app.post("/demo/race")
def demo_race():
    """Fires N concurrent requests carrying the SAME nonce at the gateway
    to demonstrate the atomicity guard under real concurrency, not just
    sequential calls (sequential calls can't show a race)."""
    resource = "https://demo.local/api/resource"
    requirements = PaymentRequirements(amount="1000", pay_to="merchant-demo", resource=resource)
    payload = PaymentPayload(
        payer="agent-demo",
        resource=resource,
        amount="1000",
        pay_to="merchant-demo",
        nonce=f"nonce-race-{uuid_suffix()}",
    )
    request = RequestContext(
        method="GET",
        path="/api/resource",
        resource=resource,
        merchant="merchant-demo",
        request_id="req-race",
    )
    issued_at = time.time()
    race_gateway = AegisGateway(
        adapter=MockX402Adapter(), policy=policy, ledger=ledger, atomicity=atomicity
    )

    results = []
    lock = threading.Lock()

    def worker():
        outcome = race_gateway.inspect(payload, requirements, request, issued_at)
        with lock:
            results.append(outcome["decision"])

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {
        "concurrent_requests": len(threads),
        "allowed": results.count("ALLOW"),
        "blocked": results.count("BLOCK"),
        "expected": "exactly 1 ALLOW, the rest BLOCK",
    }


@app.get("/demo/ledger")
def demo_ledger():
    if not ledger.path.exists():
        return {"events": []}

    events = []
    for line in ledger.path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))

    return {"events": events[-50:]}


@app.get("/demo/ledger/verify")
def demo_ledger_verify():
    ok, broken_at, count = ledger.verify_chain()
    return {"chain_intact": ok, "broken_at_event_id": broken_at, "event_count": count}

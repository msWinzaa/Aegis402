"""Attack-scenario tests beyond the original binding/replay/settlement
smoke tests. These exercise the guards this audit added or corrected:
scheme/network/asset binding, policy edges, freshness of the payload's own
signed window, execution guard edges, real concurrency (not just
sequential calls), and threat-ledger tamper-evidence + restart
continuity.
"""

import threading
import time

import pytest

from aegis402.atomicity import AtomicityGuard
from aegis402.gateway import AegisGateway
from aegis402.ledger import ThreatLedger
from aegis402.models import PaymentPayload, PaymentRequirements, RequestContext, SettlementResult
from aegis402.policy import Policy
from aegis402.settlement import verify_settlement_integrity
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


# ---------------------------------------------------------------------------
# Context binding: scheme / network / asset substitution
# ---------------------------------------------------------------------------

def test_network_substitution_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.network = "eip155:1"  # different chain than requirements

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "network mismatch" in decision["checks"]["context_binding"]


def test_asset_substitution_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.asset = "USDT"  # cheaper/different asset than required

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "asset mismatch" in decision["checks"]["context_binding"]


def test_scheme_substitution_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.scheme = "deferred"

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "scheme mismatch" in decision["checks"]["context_binding"]


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def test_amount_over_policy_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.amount = req.amount = "999999999"

    policy = Policy(max_amount=100_000)
    decision = AegisGateway(MockX402Adapter(), policy=policy).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"


def test_negative_amount_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.amount = req.amount = "-500"

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "negative amount" in decision["checks"]["policy"]


def test_disallowed_merchant_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    policy = Policy(allowed_merchants={"someone-else"})
    decision = AegisGateway(MockX402Adapter(), policy=policy).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "merchant not allowed" in decision["checks"]["policy"]


def test_disallowed_network_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    policy = Policy(allowed_networks={"eip155:8453"})
    decision = AegisGateway(MockX402Adapter(), policy=policy).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "network not allowed" in decision["checks"]["policy"]


# ---------------------------------------------------------------------------
# Freshness: stale requirement vs. expired signed authorization window
# ---------------------------------------------------------------------------

def test_stale_requirement_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    decision = AegisGateway(MockX402Adapter()).inspect(
        payload, req, ctx, issued_at=time.time() - 1000
    )
    assert decision["decision"] == "BLOCK"
    assert "expired" in decision["checks"]["freshness"]


def test_future_issued_at_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    decision = AegisGateway(MockX402Adapter()).inspect(
        payload, req, ctx, issued_at=time.time() + 1000
    )
    assert decision["decision"] == "BLOCK"
    assert "future" in decision["checks"]["freshness"]


def test_expired_payload_authorization_window_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.valid_before = int(time.time()) - 60  # payer's own signed window lapsed

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "payload_validity" in decision["checks"]
    assert "expired" in decision["checks"]["payload_validity"]


def test_not_yet_valid_payload_authorization_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    payload.valid_after = int(time.time()) + 3600

    decision = AegisGateway(MockX402Adapter()).inspect(payload, req, ctx, time.time())
    assert decision["decision"] == "BLOCK"
    assert "not yet valid" in decision["checks"]["payload_validity"]


# ---------------------------------------------------------------------------
# Execution guard
# ---------------------------------------------------------------------------

def test_excessive_execution_cost_is_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()

    decision = AegisGateway(MockX402Adapter()).inspect(
        payload, req, ctx, time.time(), estimated_cost=999_999_999
    )
    assert decision["decision"] == "BLOCK"
    assert "execution cost" in decision["checks"]["execution"]


# ---------------------------------------------------------------------------
# Settlement integrity: post-settlement facts, not just self-consistency
# ---------------------------------------------------------------------------

def test_settlement_payer_mismatch_is_blocked():
    payload, req, _ = base_case()
    result = SettlementResult(
        success=True,
        tx_hash="0xabc",
        payer="someone-else",  # facilitator says a different address paid
        settled_network=req.network,
    )
    ok, reason = verify_settlement_integrity(payload, req, result)
    assert ok is False
    assert "payer" in reason


def test_settlement_network_mismatch_is_blocked():
    payload, req, _ = base_case()
    result = SettlementResult(
        success=True,
        tx_hash="0xabc",
        payer=payload.payer,
        settled_network="eip155:1",  # settled on the wrong chain
    )
    ok, reason = verify_settlement_integrity(payload, req, result)
    assert ok is False
    assert "network" in reason


def test_settlement_without_post_settlement_facts_still_passes_self_consistency():
    # Mirrors what a facilitator that only returns the v2-core-guaranteed
    # fields (no bonus "amount" field) looks like: self-consistency still
    # gates it, but we don't claim more than that -- see settlement.py.
    payload, req, _ = base_case()
    result = SettlementResult(success=True, tx_hash="0xabc")
    ok, _ = verify_settlement_integrity(payload, req, result)
    assert ok is True


# ---------------------------------------------------------------------------
# Atomicity under real concurrency (not just sequential calls)
# ---------------------------------------------------------------------------

def test_concurrent_reserve_only_one_winner():
    guard = AtomicityGuard()
    nonce = "race-nonce"
    outcomes = []
    lock = threading.Lock()

    def worker():
        ok, _ = guard.reserve(nonce)
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 49


def test_concurrent_gateway_inspect_only_one_allow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload, req, ctx = base_case()
    gateway = AegisGateway(MockX402Adapter())

    decisions = []
    lock = threading.Lock()

    def worker():
        outcome = gateway.inspect(payload, req, ctx, time.time())
        with lock:
            decisions.append(outcome["decision"])

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert decisions.count("ALLOW") == 1
    assert decisions.count("BLOCK") == 19


# ---------------------------------------------------------------------------
# Threat ledger: tamper-evidence and restart continuity
# ---------------------------------------------------------------------------

def test_ledger_chain_detects_tampering(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = ThreatLedger(path=str(path))
    ledger.record("PAYMENT_ALLOWED", {"n": 1})
    ledger.record("PAYMENT_BLOCKED", {"n": 2})
    ledger.record("PAYMENT_ALLOWED", {"n": 3})

    ok, broken_at, count = ledger.verify_chain()
    assert ok is True
    assert count == 3

    # Tamper with the middle record's data without recomputing the chain.
    lines = path.read_text(encoding="utf-8").splitlines()
    import json

    middle = json.loads(lines[1])
    middle["data"] = {"n": "tampered"}
    lines[1] = json.dumps(middle, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, broken_at, _ = ledger.verify_chain()
    assert ok is False
    assert broken_at is not None


def test_ledger_chain_survives_process_restart(tmp_path):
    path = tmp_path / "ledger.jsonl"

    ledger_a = ThreatLedger(path=str(path))
    ledger_a.record("PAYMENT_ALLOWED", {"n": 1})
    ledger_a.record("PAYMENT_ALLOWED", {"n": 2})

    # Simulate a process restart: a brand-new ThreatLedger instance must
    # resume the chain from disk, not silently reset to genesis.
    ledger_b = ThreatLedger(path=str(path))
    assert ledger_b._previous_hash == ledger_a._previous_hash
    ledger_b.record("PAYMENT_ALLOWED", {"n": 3})

    ok, broken_at, count = ledger_b.verify_chain()
    assert ok is True
    assert count == 3

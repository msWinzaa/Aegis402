from .atomicity import AtomicityGuard
from .binding import check_context_binding, binding_fingerprint
from .execution import ExecutionPolicy, check_execution_cost
from .freshness import check_freshness, check_payload_validity_window
from .ledger import ThreatLedger
from .policy import Policy, check_policy
from .settlement import verify_settlement_integrity


class AegisGateway:
    def __init__(
        self,
        adapter,
        policy=None,
        execution_policy=None,
        ledger=None,
        atomicity=None,
    ):
        self.adapter = adapter
        self.policy = policy or Policy()
        self.execution_policy = execution_policy or ExecutionPolicy()
        self.ledger = ledger or ThreatLedger()
        self.atomicity = atomicity or AtomicityGuard()

    def inspect(self, payload, requirements, request, issued_at, estimated_cost=0):
        checks = {}
        fingerprint = binding_fingerprint(payload, requirements, request)

        ok, reason = check_context_binding(payload, requirements, request)
        checks["context_binding"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, "context mismatch")

        ok, reason = check_policy(payload, request, self.policy)
        checks["policy"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, reason)

        ok, reason = check_freshness(requirements, issued_at)
        checks["freshness"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, reason)

        ok, reason = check_payload_validity_window(payload)
        checks["payload_validity"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, reason)

        ok, reason = check_execution_cost(estimated_cost, self.execution_policy)
        checks["execution"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, reason)

        # Reserve the nonce before calling out to the adapter. verify()
        # doesn't move funds so calling it unreserved isn't itself unsafe,
        # but reserving first fails fast on a duplicate/racing request
        # without spending an external verify() round trip, and keeps the
        # "only one caller can ever reach settle() for a given nonce"
        # property obviously true by construction rather than by ordering
        # accident.
        ok, reason = self.atomicity.reserve(payload.nonce)
        checks["atomicity"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            return self._block(checks, fingerprint, reason)

        ok, reason = self.adapter.verify(payload, requirements)
        checks["x402_verification"] = "PASS" if ok else f"BLOCK: {reason}"
        if not ok:
            self.atomicity.release(payload.nonce)
            return self._block(checks, fingerprint, reason)

        settlement = self.adapter.settle(payload, requirements)
        ok, reason = verify_settlement_integrity(payload, requirements, settlement)
        checks["settlement_integrity"] = "PASS" if ok else f"BLOCK: {reason}"

        if not ok:
            self.atomicity.release(payload.nonce)
            return self._block(checks, fingerprint, reason)

        event_id = self.ledger.record(
            "PAYMENT_ALLOWED",
            {"fingerprint": fingerprint, "nonce": payload.nonce, "checks": checks},
        )

        return {
            "decision": "ALLOW",
            "reason": "payment passed main security gate",
            "checks": checks,
            "fingerprint": fingerprint,
            "event_id": event_id,
        }

    def _block(self, checks, fingerprint, reason):
        event_id = self.ledger.record(
            "PAYMENT_BLOCKED",
            {"fingerprint": fingerprint, "reason": reason, "checks": checks},
        )
        return {
            "decision": "BLOCK",
            "reason": reason,
            "checks": checks,
            "fingerprint": fingerprint,
            "event_id": event_id,
        }

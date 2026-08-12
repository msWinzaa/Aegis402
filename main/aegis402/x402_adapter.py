"""x402 integration boundary.

main does not implement payment verification or settlement itself --
it delegates that to the x402 protocol via this module, and only gates
what happens around it (binding, policy, freshness, atomicity, settlement
integrity, execution, ledger). This file defines main's own small
adapter interface (`verify` / `settle`) and two implementations of it:

- MockX402Adapter: deterministic, no network calls, used by the demo and
  the test suite. It never asserts anything a real facilitator would
  assert (no real signature check, no real balance check). Its only job
  is to make the *rest* of the gateway exercisable and testable without a
  live wallet/facilitator.

- X402FacilitatorAdapter: a real integration against the official x402
  Python SDK (PyPI package "x402", https://pypi.org/project/x402/, source
  at https://github.com/x402-foundation/x402). It calls out to a remote
  x402 facilitator's /verify and /settle endpoints over HTTP using the
  SDK's HTTPFacilitatorClientSync, and translates main's own
  PaymentPayload/PaymentRequirements into the wire format defined by the
  x402 v2 specification (specs/x402-specification-v2.md and
  specs/transports-v2/http.md in that repository).

Source-of-truth notes for the mapping below (checked against the official
docs/spec as of this writing, not invented):
  - PaymentRequirements wire fields: scheme, network, maxAmountRequired,
    resource, payTo, maxTimeoutSeconds, asset, extra.
  - "exact" EVM PaymentPayload wire shape: {x402Version, scheme, network,
    payload: {signature, authorization: {from, to, value, validAfter,
    validBefore, nonce}}}.
  - SettlementResponse only guarantees: success, errorReason, transaction,
    network, payer -- NOT a settled amount (see settlement.py docstring).
  - `x402.http.HTTPFacilitatorClientSync(url=...)` is the documented sync
    HTTP client to a remote facilitator; `x402ResourceServerSync` /
    `x402FacilitatorSync` are documented as sharing the same
    verify(payload, requirements) / settle(payload, requirements) method
    shape as their async counterparts.

Because this SDK is released frequently (multiple releases a month) and
this module cannot execute against a live installation while being
written, every call into the SDK below is wrapped so that a shape/name
mismatch raises a clear X402IntegrationError instead of failing silently
or producing a misleading ALLOW. Pin your installed `x402` version and
re-check this mapping against that version's changelog before relying on
X402FacilitatorAdapter for anything beyond a sandbox/testnet facilitator.
"""

from __future__ import annotations

from dataclasses import dataclass


class X402Adapter:
    # main's own interface boundary -- not part of the x402 protocol.
    # Concrete adapters translate to/from the real x402 SDK or facilitator.
    def verify(self, payload, requirements):
        raise NotImplementedError

    def settle(self, payload, requirements):
        raise NotImplementedError


class X402IntegrationError(RuntimeError):
    """Raised when the installed x402 SDK doesn't match the mapping this
    adapter expects, so a version mismatch fails loudly instead of
    silently mis-verifying a payment."""


@dataclass
class MockX402Adapter(X402Adapter):
    """Deterministic, offline stand-in for demo/test use only.

    Does NOT perform real signature verification, real balance checks, or
    real settlement. `payload.signature == "invalid"` is the only failure
    mode it recognises, purely so the demo and tests can exercise the
    BLOCK path deterministically. See SECURITY.md: this adapter must never
    be used to protect real funds.
    """

    settlement_should_fail: bool = False

    def verify(self, payload, requirements):
        if payload.signature == "invalid":
            return False, "invalid payment signature"
        return True, "x402 verification passed (mock -- not a real signature check)"

    def settle(self, payload, requirements):
        from .models import SettlementResult

        if self.settlement_should_fail:
            return SettlementResult(success=False, reason="mock settlement failure")

        return SettlementResult(
            success=True,
            tx_hash="0xDEMO_" + payload.nonce[:12],
            settled_network=payload.network,
            payer=payload.payer,
            settled_amount=payload.amount,
        )


class X402FacilitatorAdapter(X402Adapter):
    """Real integration against an x402 facilitator via the official SDK.

    Parameters
    ----------
    facilitator_url:
        Base URL of an x402 facilitator (e.g. "https://x402.org/facilitator"
        for the public testnet facilitator, or your own).
    x402_version:
        Protocol version to stamp on outgoing payloads. Defaults to 2
        (current at the time of writing); override if your facilitator
        still speaks v1.
    """

    def __init__(self, facilitator_url: str, x402_version: int = 2):
        self.facilitator_url = facilitator_url
        self.x402_version = x402_version
        self._client = None  # lazily constructed -- see _get_client()

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from x402.http import HTTPFacilitatorClientSync
        except ImportError as exc:
            raise X402IntegrationError(
                "The official x402 Python SDK is not installed. "
                "Install it with one of: pip install 'x402[httpx]' or "
                "'x402[requests]' (see https://pypi.org/project/x402/)."
            ) from exc
        self._client = HTTPFacilitatorClientSync(url=self.facilitator_url)
        return self._client

    def _to_wire_requirements(self, requirements) -> dict:
        return {
            "scheme": requirements.scheme,
            "network": requirements.network,
            "maxAmountRequired": requirements.amount,
            "resource": requirements.resource,
            "payTo": requirements.pay_to,
            "maxTimeoutSeconds": requirements.max_timeout_seconds,
            "asset": requirements.asset,
            "extra": {},
        }

    def _to_wire_payload(self, payload) -> dict:
        return {
            "x402Version": self.x402_version,
            "scheme": payload.scheme,
            "network": payload.network,
            "payload": {
                "signature": payload.signature,
                "authorization": {
                    "from": payload.payer,
                    "to": payload.pay_to,
                    "value": payload.amount,
                    "validAfter": str(payload.valid_after) if payload.valid_after is not None else "0",
                    "validBefore": str(payload.valid_before) if payload.valid_before is not None else "0",
                    "nonce": payload.nonce,
                },
            },
        }

    def _sdk_types(self):
        # The module path for the SDK's own pydantic models has moved
        # across releases (see python/x402/schemas/payments.py in current
        # releases; older releases exposed x402.types). Try both rather
        # than hard-coding one and breaking silently on upgrade/downgrade.
        try:
            from x402.schemas.payments import (
                PaymentPayload as SDKPaymentPayload,
                PaymentRequirements as SDKPaymentRequirements,
            )
            return SDKPaymentPayload, SDKPaymentRequirements
        except ImportError:
            pass
        try:
            from x402.types import (
                PaymentPayload as SDKPaymentPayload,
                PaymentRequirements as SDKPaymentRequirements,
            )
            return SDKPaymentPayload, SDKPaymentRequirements
        except ImportError as exc:
            raise X402IntegrationError(
                "Could not locate the x402 SDK's PaymentPayload/"
                "PaymentRequirements pydantic models under either "
                "x402.schemas.payments or x402.types. The installed x402 "
                "SDK version likely changed its module layout -- check "
                "https://github.com/x402-foundation/x402 for the current "
                "path and update X402FacilitatorAdapter._sdk_types()."
            ) from exc

    def _build_sdk_objects(self, payload, requirements):
        sdk_payload_cls, sdk_requirements_cls = self._sdk_types()
        try:
            sdk_requirements = sdk_requirements_cls.model_validate(
                self._to_wire_requirements(requirements)
            )
            sdk_payload = sdk_payload_cls.model_validate(self._to_wire_payload(payload))
        except Exception as exc:  # pydantic ValidationError or similar
            raise X402IntegrationError(
                f"Could not translate main's payment objects into the "
                f"installed x402 SDK's wire schema: {exc}. This usually "
                f"means the SDK version's field names differ from the "
                f"mapping documented at the top of x402_adapter.py -- "
                f"re-check against your installed x402 version."
            ) from exc
        return sdk_payload, sdk_requirements

    def verify(self, payload, requirements):
        client = self._get_client()
        sdk_payload, sdk_requirements = self._build_sdk_objects(payload, requirements)
        try:
            result = client.verify(sdk_payload, sdk_requirements)
        except AttributeError as exc:
            raise X402IntegrationError(
                "The installed x402 SDK's HTTPFacilitatorClientSync has no "
                "verify(payload, requirements) method matching the "
                "documented shape. Check the installed SDK's release notes."
            ) from exc

        is_valid = getattr(result, "is_valid", None)
        if is_valid is None:
            is_valid = getattr(result, "isValid", False)
        reason = getattr(result, "invalid_reason", None) or getattr(
            result, "errorReason", "x402 verification failed"
        )
        if is_valid:
            return True, "x402 verification passed"
        return False, str(reason)

    def settle(self, payload, requirements):
        from .models import SettlementResult

        client = self._get_client()
        sdk_payload, sdk_requirements = self._build_sdk_objects(payload, requirements)
        try:
            result = client.settle(sdk_payload, sdk_requirements)
        except AttributeError as exc:
            raise X402IntegrationError(
                "The installed x402 SDK's HTTPFacilitatorClientSync has no "
                "settle(payload, requirements) method matching the "
                "documented shape. Check the installed SDK's release notes."
            ) from exc

        success = bool(getattr(result, "success", False))
        tx_hash = getattr(result, "transaction", None) or None
        settled_network = getattr(result, "network", None)
        payer = getattr(result, "payer", None)
        # Not part of the core v2 SettlementResponse -- only present if this
        # facilitator deployment opts into returning it. See settlement.py.
        settled_amount = getattr(result, "amount", None)
        reason = getattr(result, "errorReason", None) if not success else None

        return SettlementResult(
            success=success,
            tx_hash=tx_hash,
            reason=reason,
            settled_network=settled_network,
            payer=payer,
            settled_amount=settled_amount,
        )

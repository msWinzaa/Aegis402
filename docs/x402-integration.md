# x402 Integration

Aegis uses the official x402 Python SDK rather than reimplementing x402. The current reference supplied for this implementation is x402 Python 2.8.0.

The adapter maps Aegis's internal payment representation to x402 v2 `PaymentPayload` and `PaymentRequirements`, then calls `HTTPFacilitatorClientSync.verify`, `settle` and `get_supported`.

The critical path remains:

payment requirements -> Aegis deterministic gate -> x402 verification -> settlement -> independent settlement verification -> resource release.

The mock adapter remains available for deterministic tests. Live tests require the SDK, facilitator URL and network/RPC configuration.

# Security

main v0.1 is an experimental implementation. It has not undergone an independent security audit. It must not be used to protect production payment flows or real funds.

## Implemented properties

### Context binding

The gateway rejects a payment presented with a different resource, merchant, pay-to address, amount, scheme, network or asset from the values against which it was authorised.

### Policy

The gateway applies configured amount ceilings and endpoint, merchant and network restrictions before verification and settlement.

### Freshness

The gateway rejects stale payment requirements and checks the signed authorization window when the payment scheme supplies one.

### Atomicity

Within one running process, the nonce guard permits only one caller to reach settlement for a given nonce.

### Settlement integrity

A failed settlement, missing transaction hash, or returned payer or network mismatch causes the request to be rejected. The available settlement fields determine the extent of the check.

### Ledger

The local ledger uses a hash chain. Modifications to existing records can therefore be detected. The chain is persisted across process restarts.

## Limitations

Atomicity is process-local. The current guard uses an in-memory set protected by a thread lock. It does not coordinate multiple processes or replicas. A production implementation requires shared transactional state.

Settlement integrity cannot independently establish the amount transferred on chain. The core x402 settlement response does not provide that fact as an interoperable field. Independent transaction inspection is required when the settled amount must be established from chain state.

The execution guard does not measure gas or compute usage. The prototype receives an estimated cost from the caller and compares it with a configured ceiling.

The mock adapter performs no live cryptographic verification. It exists for deterministic local execution and tests.

The facilitator adapter is an integration boundary for the x402 Python SDK. Its field mapping must be checked against the exact SDK version used for deployment.

The ledger is tamper-evident rather than tamper-proof. A process with write access can replace the ledger with a new internally consistent chain. External anchoring is required for stronger provenance.

The freshness value for a payment requirement is local server state. The signed validity window in the payment payload is the part committed by the payer when supported by the scheme.

## Reporting

Security issues should be reported privately to the repository maintainers before public disclosure.

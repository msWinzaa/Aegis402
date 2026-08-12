# Attack Scenarios

| Scenario | Control | Status |
|---|---|---|
| Cross-resource substitution | Context binding | Implemented |
| Scheme substitution | Context binding | Implemented |
| Network substitution | Context binding | Implemented |
| Asset substitution | Context binding | Implemented |
| Sequential replay | Atomicity and idempotency | Implemented |
| Concurrent nonce race | Atomicity and idempotency | Implemented |
| Stale 402 requirement | Freshness | Implemented |
| Premature or expired authorization | Validity window | Implemented |
| Excessive amount | Policy | Implemented |
| Disallowed merchant | Policy | Implemented |
| Disallowed network | Policy | Implemented |
| Invalid signature input | Adapter validation path | Implemented in prototype adapter |
| Failed settlement | Settlement integrity | Implemented |
| Settlement payer mismatch | Settlement integrity | Implemented when returned by adapter |
| Gas or execution abuse | Execution guard | Prototype; caller-reported cost |
| Free resource release | Settlement and resource-release rule | Partial |
| Asset theft | Context and execution constraints | Partial |
| Ledger modification | Hash chain | Detection |

The exact guarantees and limitations are documented in `SECURITY.md`.

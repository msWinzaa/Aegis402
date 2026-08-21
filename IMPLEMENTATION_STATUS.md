# Aegis v1.0 Hardening Status

| Capability | Status |
|---|---|
| Deterministic payment security | IMPLEMENTED |
| External consumer wallet | IMPLEMENTED |
| Ed25519 node identity | IMPLEMENTED |
| Signed threat reports | IMPLEMENTED |
| Authenticated peers | IMPLEMENTED |
| Bounded Sybil influence | IMPLEMENTED |
| Evidence-weighted reputation | IMPLEMENTED |
| Threat-intelligence PBFT-style consensus | EXPERIMENTAL |
| Merkle batching and proof verification | IMPLEMENTED |
| Local anchor backend | IMPLEMENTED |
| EVM anchor backend | EXPERIMENTAL |
| Independent EVM settlement observation | EXPERIMENTAL |
| Official x402 v2 adapter | IMPLEMENTED |
| Live facilitator integration | PARTIAL (requires external facilitator/network) |
| Secret-provider abstraction | IMPLEMENTED |
| HSM integration | EXPERIMENTAL (provider interface) |
| Network partition tolerance | IMPLEMENTED |
| Privacy minimisation / pseudonyms | IMPLEMENTED |
| Anonymous reputation / differential privacy | NOT IMPLEMENTED |

## Explicit assumptions

Sybil resistance is bounded influence, quarantine, diversity and admission cost; it is not perfect Sybil prevention.

Consensus assumes static authenticated membership and at most `f` Byzantine members for `n >= 3f+1`.

EVM settlement verification requires an RPC endpoint and mechanism-specific event decoding when payer/recipient/amount must be established from chain logs.

External anchoring is only independently witnessed when an external backend actually records the Merkle root.

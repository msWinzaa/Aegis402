# Security Model

Hard controls have precedence over risk, reputation and distributed intelligence.

Hard failures include invalid signatures, binding failures, stale authorization, nonce replay/race, policy violations and settlement mismatch. They fail closed.

Distributed systems are advisory unless a local hard policy explicitly promotes a condition to BLOCK. Consensus is limited to threat-intelligence state.

The main trust assumptions are the consumer wallet, configured payment requirements, trusted peer bootstrap, node signing keys, RPC endpoints used for independent settlement verification and any configured external anchor.

# Architecture

One Aegis agent runs per device or trust domain. Local policy, payment state, nonce state, ledger, node identity and threat cache remain local.

Peer communication, reputation and threat-intelligence consensus operate asynchronously outside the critical x402 path.

The consumer wallet remains externally owned. Aegis does not custody or request consumer private keys.

The x402 adapter is an explicit boundary to the official SDK and facilitator.

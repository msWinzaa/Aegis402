# Security Model

Aegis protects the application boundary around autonomous x402 payments. Hard cryptographic/protocol/payment controls are authoritative. Risk and distributed intelligence are advisory.

Aegis never accepts or stores a consumer private key or seed phrase. `AEGIS_NODE_SIGNING_KEY` is exclusively a node identity credential.

See `docs/threat-model.md` and `docs/security-model.md` for details.

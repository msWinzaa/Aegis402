# Threat Model

Attackers may manipulate HTTP requests, payment fields, replay or race authorizations, send forged/modified/replayed peer messages, create low-trust identities, flood reports, delay or withhold peer traffic and poison reputation.

Protected assets are payment context, resource access, nonce/idempotency state, ledger integrity, node identity trust and threat intelligence.

Out of scope: compromised host/runtime, unrestricted filesystem compromise, broken cryptographic primitives, compromised consumer wallet and blockchain consensus failure.

Invariants: payment matches its resource/merchant; hard policy is satisfied; authorization is fresh; nonce is single-use; settlement remains consistent with available facilitator facts; peer messages are attributable and integrity-protected; peer intelligence cannot override local security.

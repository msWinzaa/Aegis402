# Peer Network Protocol

Peer messages use Ed25519-signed envelopes with sender identity, message ID, timestamp, TTL and report content. Nodes maintain an explicit trusted/revoked state.

The protocol rejects unknown identities, revoked keys, invalid signatures, stale messages, unsupported versions, duplicate message IDs and messages above the configured size/rate limits.

Threat reports contain a version, report ID, reporter, timestamps, target, classification, severity, evidence references, confidence, sequence and signature. Report verification is separate from storage.

The network is asynchronous. Local payment security continues when peers are unavailable.

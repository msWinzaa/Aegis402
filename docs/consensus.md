# Threat-Intelligence Consensus

Aegis uses a static-membership PBFT-style protocol for advisory threat-intelligence state. It is outside the x402 payment path.

## Safety model

For `n >= 3f + 1`, the protocol tolerates up to `f = floor((n-1)/3)` Byzantine members while authenticated membership and signatures remain valid. A commit requires a quorum of `2f+1` distinct members for both prepare and commit evidence.

The prototype implements signed PRE-PREPARE, PREPARE and COMMIT messages, epoch/sequence numbers, quorum calculation and signature verification. It does not provide automatic membership discovery or a globally persistent replicated state machine.

## Invariants

- unknown or revoked identities cannot vote;
- forged or replayed messages are rejected;
- one node cannot form a quorum alone;
- conflicting digests are not merged;
- consensus output cannot authorize or settle payments;
- partitions stop progress rather than weakening safety.

## Remaining assumption

Membership is administratively bootstrapped. Dynamic membership changes and durable multi-node state replication remain deployment concerns.

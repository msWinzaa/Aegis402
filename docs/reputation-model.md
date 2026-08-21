# Reputation Model

Reputation is deterministic evidence aggregation, not one-node-one-vote consensus.

Each observation is weighted by signed provenance, reporter trust, evidence quality, confidence, age decay and bounded identity influence. New identities are quarantined; correlated identities receive reduced influence; source diversity is required for meaningful corroboration.

The stored result includes contributing report IDs, reporters, decay and influence values, so a node can explain why a score changed.

A score never converts an invalid payment into an allowed payment.

# Ledger and External Anchoring

The local ledger remains a hash-chained JSONL audit log. A Merkle tree can batch canonical events into an authenticated root.

The root can be recorded through an `AnchorBackend`. `LocalAnchorBackend` is deterministic development infrastructure. `EVMAnchorBackend` submits one root per batch to an operator-configured contract exposing `anchor(bytes32)`.

A Merkle proof contains sibling hashes and direction bits. Proof verification requires only the event, proof and root; the original SQLite database is not required.

External anchoring changes the guarantee from local tamper evidence to externally witnessed existence at the anchor transaction. It does not make local storage immutable.

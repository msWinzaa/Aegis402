"""Threat ledger.

A local hash-chained, append-only audit log. Each record commits to the
hash of the previous record, so anyone holding the file can detect
after-the-fact edits or deletions to past entries by recomputing the chain
(see verify_chain). This is tamper-EVIDENT, not tamper-PROOF and not a
decentralised ledger: the file lives on local disk with no access control
of its own, so an attacker with write access to the file (or to the
running process) can truncate the file and start a fresh, internally
-consistent chain, or edit the last record and recompute forward from
there. Detecting that requires an external, independent copy of the chain
head (out of scope for v0.1 -- see docs/roadmap.md v0.2/v0.3 for
externally-anchored/signed evidence).

Process-restart correctness
-----------------------------
The chain's `previous_hash` pointer must survive process restarts, or a
fresh process would silently start a new chain at genesis while the file
already has entries -- breaking continuity without any error. On init this
class reads the last line of an existing ledger file (if any) and resumes
the chain from its event_hash, rather than assuming genesis.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path

GENESIS_HASH = "0" * 64


def _event_hash(event_without_hash: dict) -> str:
    canonical = json.dumps(event_without_hash, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class ThreatLedger:
    def __init__(self, path="aegis402_ledger.jsonl"):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._previous_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "event_hash" in event:
                    last_hash = event["event_hash"]
        return last_hash

    def record(self, event_type, data):
        with self._lock:
            event_id = str(uuid.uuid4())
            event = {
                "event_id": event_id,
                "timestamp": time.time(),
                "event_type": event_type,
                "data": data,
                "previous_hash": self._previous_hash,
            }
            event_hash = _event_hash(event)
            event["event_hash"] = event_hash

            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")

            self._previous_hash = event_hash
            return event_id

    def verify_chain(self):
        """Recompute the hash chain from disk and check it is intact.

        Returns (ok, broken_at_event_id_or_None, event_count).
        """
        if not self.path.exists():
            return True, None, 0

        expected_previous = GENESIS_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                stored_hash = event.get("event_hash")
                recomputed = {k: v for k, v in event.items() if k != "event_hash"}
                if event.get("previous_hash") != expected_previous:
                    return False, event.get("event_id"), count
                if _event_hash(recomputed) != stored_hash:
                    return False, event.get("event_id"), count
                expected_previous = stored_hash
                count += 1

        return True, None, count

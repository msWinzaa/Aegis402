"""Atomicity / idempotency guard.

Reserves a payment nonce exactly once so that a valid payment cannot be
used to unlock the resource twice (replay) and so that two concurrent
requests racing on the same nonce cannot both proceed to settlement.

Scope of the guarantee
-----------------------
This is an in-memory, single-process guard: reserve()/release() are
protected by a single threading.Lock, so it correctly serializes concurrent
requests *within one running process* (see tests/test_attacks.py for a
real multi-thread race test, not just sequential calls). It provides NO
guarantee across process restarts (the lock table is empty again after a
restart -- a nonce settled just before a crash could be reserved again
after restart) and NO guarantee across multiple processes/replicas behind
a load balancer, since each process has its own independent `_locked` set.
A production deployment needs a shared, transactional store (e.g. a
database unique constraint or Redis SETNX) keyed by nonce, as noted below.
"""

import threading


class AtomicityGuard:
    # In-memory prototype store. Replace with transactional shared storage
    # (a DB unique constraint or an atomic distributed lock) for a
    # multi-process or crash-safe deployment.
    def __init__(self):
        self._lock = threading.Lock()
        self._locked = set()

    def reserve(self, nonce):
        with self._lock:
            if nonce in self._locked:
                return False, "nonce already locked"
            self._locked.add(nonce)
            return True, "nonce reserved"

    def release(self, nonce):
        with self._lock:
            self._locked.discard(nonce)

    def is_locked(self, nonce):
        with self._lock:
            return nonce in self._locked

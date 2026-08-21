import threading
class AtomicityGuard:
    def __init__(self,store=None): self.store=store; self._lock=threading.Lock(); self._locked=set(); self._consumed=set()
    def reserve(self,nonce,fingerprint=''):
        with self._lock:
            if nonce in self._locked or nonce in self._consumed:return False,'nonce already consumed or reserved'
            if self.store and not self.store.reserve_nonce(nonce,fingerprint):return False,'nonce already consumed or reserved'
            self._locked.add(nonce); return True,'nonce reserved'
    def commit(self,nonce):
        with self._lock:
            self._consumed.add(nonce)
            if self.store:self.store.consume_nonce(nonce)
            self._locked.discard(nonce)
    def release(self,nonce):
        with self._lock:
            if self.store:self.store.release_nonce(nonce)
            self._locked.discard(nonce)
    def is_locked(self,nonce):
        with self._lock:return nonce in self._locked

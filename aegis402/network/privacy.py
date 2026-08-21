from __future__ import annotations
import hashlib,hmac
class PrivateReputation:
    """Prototype privacy layer: replaces raw target identifiers with keyed pseudonyms.
    This is not differential privacy or a cryptographic MPC protocol."""
    def __init__(self,key:str): self.key=key.encode()
    def pseudonym(self,target:str)->str:return hmac.new(self.key,target.encode(),hashlib.sha256).hexdigest()
    def aggregate(self,reports):
        buckets={}
        for r in reports:
            p=self.pseudonym(r['target']);b=buckets.setdefault(p,{'reports':0,'severity':{}});b['reports']+=1;b['severity'][r['severity']]=b['severity'].get(r['severity'],0)+1
        return buckets

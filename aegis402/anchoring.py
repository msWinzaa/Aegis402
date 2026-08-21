
from __future__ import annotations
import hashlib,json,time,uuid
from dataclasses import dataclass
from .crypto import canonical_json

def h(x:bytes)->str:return hashlib.sha256(x).hexdigest()
def merkle_root(items):
    layer=[h(canonical_json(x).encode()) for x in items]
    if not layer:return h(b"")
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        layer=[h(bytes.fromhex(layer[i])+bytes.fromhex(layer[i+1])) for i in range(0,len(layer),2)]
    return layer[0]
def merkle_proof(items,index):
    hashes=[h(canonical_json(x).encode()) for x in items]; idx=index; proof=[]
    while len(hashes)>1:
        if len(hashes)%2: hashes.append(hashes[-1])
        sib=idx-1 if idx%2 else idx+1
        proof.append({"hash":hashes[sib],"left":idx%2==1})
        hashes=[h(bytes.fromhex(hashes[i])+bytes.fromhex(hashes[i+1])) for i in range(0,len(hashes),2)]; idx//=2
    return proof
def verify_proof(event,proof,root):
    cur=h(canonical_json(event).encode())
    for p in proof: cur=h(bytes.fromhex(p["hash"])+bytes.fromhex(cur)) if p["left"] else h(bytes.fromhex(cur)+bytes.fromhex(p["hash"]))
    return cur==root

class AnchorBackend:
    def anchor(self,root:str,metadata:dict): raise NotImplementedError
    def verify_anchor(self,anchor): raise NotImplementedError
class LocalAnchorBackend(AnchorBackend):
    def anchor(self,root,metadata):
        return {"anchor_id":str(uuid.uuid4()),"root":root,"anchored_at":time.time(),"backend":"local",**metadata}
    def verify_anchor(self,anchor): return anchor.get("backend")=="local" and bool(anchor.get("root"))
class EVMAnchorBackend(AnchorBackend):
    def __init__(self,rpc_url,contract_address,private_key=None): self.rpc_url=rpc_url; self.contract_address=contract_address; self.private_key=private_key
    def anchor(self,root,metadata):
        if not self.private_key: raise RuntimeError("EVM anchoring requires a dedicated service/node signing key")
        try:
            from web3 import Web3
            w=Web3(Web3.HTTPProvider(self.rpc_url)); acct=w.eth.account.from_key(self.private_key)
            # Contract is expected to expose anchor(bytes32); deployment ABI is operator-configured.
            abi=[{"inputs":[{"name":"root","type":"bytes32"}],"name":"anchor","outputs":[],"stateMutability":"nonpayable","type":"function"}]
            c=w.eth.contract(address=self.contract_address,abi=abi)
            tx=c.functions.anchor(bytes.fromhex(root)).build_transaction({"from":acct.address,"nonce":w.eth.get_transaction_count(acct.address),"gas":150000,"gasPrice":w.eth.gas_price})
            signed=acct.sign_transaction(tx); txh=w.eth.send_raw_transaction(signed.raw_transaction)
            return {"anchor_id":txh.hex(),"root":root,"backend":"evm","rpc_url":self.rpc_url,"contract":self.contract_address,"anchored_at":time.time()}
        except ImportError as e: raise RuntimeError("Install web3 for EVM anchoring") from e
    def verify_anchor(self,anchor):
        try:
            from web3 import Web3
            w=Web3(Web3.HTTPProvider(anchor["rpc_url"])); return w.eth.get_transaction_receipt(anchor["anchor_id"])["status"]==1
        except Exception:return False

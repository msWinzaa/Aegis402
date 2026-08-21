from __future__ import annotations
import base64, os, time
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class NodeIdentity:
    algorithm='Ed25519'
    def __init__(self,node_id:str,key_material:str|None=None,key_path:str='aegis_node_key.pem'):
        self.node_id=node_id; self.key_path=Path(key_path); self._revoked=set(); self._key=self._load_or_create(key_material)
    def _load_or_create(self,key_material):
        if key_material:
            try:
                if key_material.strip().startswith('-----BEGIN'): return serialization.load_pem_private_key(key_material.encode(),password=None)
                return Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_material))
            except Exception as e: raise ValueError('AEGIS_NODE_SIGNING_KEY is not a valid Ed25519 private key') from e
        if self.key_path.exists(): return serialization.load_pem_private_key(self.key_path.read_bytes(),password=None)
        key=Ed25519PrivateKey.generate(); self.key_path.parent.mkdir(parents=True,exist_ok=True); self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        try: os.chmod(self.key_path,0o600)
        except OSError: pass
        return key
    @property
    def public_key_bytes(self): return self._key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    @property
    def public_key(self): return base64.b64encode(self.public_key_bytes).decode()
    @property
    def key_id(self): return self.public_key[:16]
    def sign(self,data:bytes): return base64.b64encode(self._key.sign(data)).decode()
    @staticmethod
    def verify(public_key,data,signature):
        try: Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(base64.b64decode(signature),data); return True
        except Exception: return False
    def rotate(self):
        old=self.public_key
        old_key=self._key
        self._key=Ed25519PrivateKey.generate()
        proof_body=f"aegis-key-rotation:{self.node_id}:{old}:{self.public_key}".encode()
        continuity=base64.b64encode(old_key.sign(proof_body)).decode()
        self._revoked.add(old)
        self.key_path.write_bytes(self._key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        try: os.chmod(self.key_path,0o600)
        except OSError: pass
        return {'old_public_key':old,'new_public_key':self.public_key,'rotated_at':str(time.time()),'continuity_proof':continuity}
    def metadata(self)->dict[str,Any]: return {'node_id':self.node_id,'algorithm':self.algorithm,'public_key':self.public_key,'key_id':self.key_id}

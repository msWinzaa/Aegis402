
from __future__ import annotations
import os, stat
from pathlib import Path
from typing import Protocol
class SecretProvider(Protocol):
    def get(self,name:str)->str|None:...
class EnvSecretProvider:
    def get(self,name): return os.getenv(name)
class FileSecretProvider:
    def __init__(self,root): self.root=Path(root)
    def get(self,name):
        p=(self.root/name).resolve()
        if self.root.resolve() not in p.parents: raise ValueError("invalid secret path")
        if not p.exists(): return None
        mode=stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077: raise PermissionError(f"secret file {p} is too permissive; use 0600")
        return p.read_text().strip()
class SecretManagerProvider:
    """Adapter boundary for Vault/KMS/cloud secret managers."""
    def __init__(self,loader): self.loader=loader
    def get(self,name): return self.loader(name)
class SigningProvider(Protocol):
    def sign(self,data:bytes)->bytes:...
    def rotate(self):...
    def revoke(self):...
class KeyLifecycle:
    def __init__(self,provider): self.provider=provider
    def sign(self,data): return self.provider.sign(data)
    def rotate(self): return self.provider.rotate()
    def revoke(self): return self.provider.revoke()
def validate_production(*,tls_enabled,secret_provider_name,node_key_path,allow_insecure=False):
    if allow_insecure:return
    if not tls_enabled: raise RuntimeError("production configuration requires TLS or a TLS-terminating reverse proxy")
    if secret_provider_name in {"env","file"} and not os.getenv("AEGIS_ALLOW_BASIC_SECRET_PROVIDER"): 
        raise RuntimeError("production requires an external secret provider unless explicitly acknowledged")
    if node_key_path and Path(node_key_path).exists() and stat.S_IMODE(Path(node_key_path).stat().st_mode)&0o077:
        raise RuntimeError("node signing key file must not be group/world accessible")

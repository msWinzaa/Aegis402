from __future__ import annotations
import hmac
import os
from enum import Enum
from fastapi import Header, HTTPException

class Role(str, Enum):
    ADMIN='admin'; SECURITY='security'; POLICY='policy'; AUDITOR='auditor'; OPERATOR='operator'


def _token_for(role: Role) -> str:
    return os.getenv({Role.ADMIN:'AEGIS_ADMIN_TOKEN',Role.SECURITY:'AEGIS_SECURITY_TOKEN',Role.POLICY:'AEGIS_POLICY_TOKEN',Role.AUDITOR:'AEGIS_AUDITOR_TOKEN',Role.OPERATOR:'AEGIS_OPERATOR_TOKEN'}[role], '')

def require_role(*roles: Role, allow_development: bool=False):
    def dependency(authorization: str | None = Header(default=None)):
        env=os.getenv('AEGIS_ENV','development').lower()
        required=os.getenv('AEGIS_REQUIRE_ADMIN_AUTH', 'true' if env=='production' else 'false').lower() in {'1','true','yes','on'}
        if not required and allow_development:
            return 'development'
        if not authorization or not authorization.lower().startswith('bearer '):
            raise HTTPException(401,'administrator authentication required')
        supplied=authorization[7:].strip()
        for role in roles:
            expected=_token_for(role)
            if expected and hmac.compare_digest(supplied, expected): return role.value
        raise HTTPException(403,'insufficient administrator privileges')
    return dependency

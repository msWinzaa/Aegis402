from __future__ import annotations
import os
from dataclasses import dataclass

def _bool(name,default): return os.getenv(name,str(default)).lower() in {'1','true','yes','on'}
@dataclass(frozen=True)
class Settings:
    db_path:str=os.getenv('AEGIS_DB_PATH',os.getenv('AEGIS402_DB_PATH','aegis402.db'))
    ledger_path:str=os.getenv('AEGIS_LEDGER_PATH',os.getenv('AEGIS402_LEDGER_PATH','aegis402_ledger.jsonl'))
    adapter:str=os.getenv('AEGIS_X402_ADAPTER',os.getenv('AEGIS402_ADAPTER','mock'))
    facilitator_url:str=os.getenv('AEGIS_FACILITATOR_URL',os.getenv('AEGIS402_FACILITATOR_URL','https://x402.org/facilitator'))
    x402_version:int=int(os.getenv('AEGIS_X402_VERSION',os.getenv('AEGIS402_X402_VERSION','2')))
    x402_network:str=os.getenv('AEGIS_X402_NETWORK','eip155:84532')
    x402_asset:str=os.getenv('AEGIS_X402_ASSET','')
    node_id:str=os.getenv('AEGIS_NODE_ID',os.getenv('AEGIS402_NODE_ID','local-node'))
    node_signing_key:str=os.getenv('AEGIS_NODE_SIGNING_KEY','')
    node_key_path:str=os.getenv('AEGIS_NODE_KEY_PATH','aegis_node_key.pem')
    peer_bootstrap_token:str=os.getenv('AEGIS_PEER_BOOTSTRAP_TOKEN','')
    require_signed_threat_reports:bool=_bool('AEGIS_REQUIRE_SIGNED_THREATS',True)
    max_peer_report_bytes:int=int(os.getenv('AEGIS_MAX_PEER_REPORT_BYTES','65536'))
    max_peer_reports_per_minute:int=int(os.getenv('AEGIS_MAX_PEER_REPORTS_PER_MINUTE','60'))
    max_clock_skew_seconds:int=int(os.getenv('AEGIS_MAX_CLOCK_SKEW_SECONDS','120'))
    peer_timeout_seconds:float=float(os.getenv('AEGIS_PEER_TIMEOUT_SECONDS','3'))
    tls_enabled:bool=_bool('AEGIS_TLS_ENABLED',False)
    environment:str=os.getenv('AEGIS_ENV','development')
    rpc_url:str=os.getenv('AEGIS_RPC_URL','')
    anchor_backend:str=os.getenv('AEGIS_ANCHOR_BACKEND','local')
    anchor_contract:str=os.getenv('AEGIS_ANCHOR_CONTRACT','')
    settlement_confirmation_depth:int=int(os.getenv('AEGIS_SETTLEMENT_CONFIRMATIONS','2'))
    ai_risk_url:str=os.getenv('AEGIS_AI_RISK_URL','')
    ai_risk_required:bool=_bool('AEGIS_AI_RISK_REQUIRED',False)
    require_admin_auth:bool=_bool('AEGIS_REQUIRE_ADMIN_AUTH',False)
    demo_pay_to:str=os.getenv('AEGIS_DEMO_PAY_TO','')
    demo_price:str=os.getenv('AEGIS_DEMO_PRICE','1000')

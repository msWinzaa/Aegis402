
from __future__ import annotations
from dataclasses import dataclass,field
from typing import Any,Protocol
@dataclass(frozen=True)
class SettlementAuthorisation:
    payer:str; recipient:str; amount:str; asset:str; network:str; payment_fingerprint:str
@dataclass(frozen=True)
class SettlementObservation:
    transaction:str; payer:str|None; recipient:str|None; amount:str|None; asset:str|None; network:str
    success:bool; block_number:int|None; confirmations:int; reorg_sensitive:bool=False; raw:dict[str,Any]=field(default_factory=dict)
@dataclass(frozen=True)
class SettlementVerificationResult:
    verified:bool; mode:str; reason:str; observation:SettlementObservation|None=None
class SettlementVerifier(Protocol):
    def observe(self,authorisation:SettlementAuthorisation,tx_hash:str)->SettlementObservation:...
class EVMSettlementVerifier:
    def __init__(self,rpc_url,confirmation_depth=2,event_decoder=None):
        self.rpc_url=rpc_url; self.confirmation_depth=confirmation_depth; self.event_decoder=event_decoder
    def observe(self,authorisation,tx_hash):
        try: from web3 import Web3
        except ImportError: raise RuntimeError("web3 is required for independent EVM settlement verification")
        w=Web3(Web3.HTTPProvider(self.rpc_url)); receipt=w.eth.get_transaction_receipt(tx_hash)
        block=w.eth.block_number; bn=receipt.blockNumber; confirmations=max(0,block-bn+1)
        status=bool(receipt.status)
        decoded=self.event_decoder(receipt,authorisation) if self.event_decoder else {}
        return SettlementObservation(tx_hash,decoded.get("payer"),decoded.get("recipient"),decoded.get("amount"),decoded.get("asset",authorisation.asset),
            authorisation.network,status,bn,confirmations,bool(confirmations<self.confirmation_depth),dict(decoded))
    def verify(self,authorisation,tx_hash):
        try:o=self.observe(authorisation,tx_hash)
        except Exception as e:return SettlementVerificationResult(False,"unavailable",str(e))
        checks=[o.success,o.confirmations>=self.confirmation_depth,o.network==authorisation.network]
        for actual,expected in ((o.payer,authorisation.payer),(o.recipient,authorisation.recipient),(o.amount,authorisation.amount),(o.asset,authorisation.asset)):
            if actual is not None: checks.append(str(actual).lower()==str(expected).lower())
        if o.reorg_sensitive:return SettlementVerificationResult(False,"held","insufficient confirmation depth",o)
        return SettlementVerificationResult(all(checks),"onchain","independent settlement verification passed" if all(checks) else "settlement mismatch",o)

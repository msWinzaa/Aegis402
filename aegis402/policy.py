from dataclasses import dataclass, field
from datetime import datetime, timezone
@dataclass
class Policy:
    max_amount:int=100_000
    daily_limit:int=500_000
    monthly_limit:int=5_000_000
    approval_threshold:int=50_000
    allowed_paths:set[str]=field(default_factory=lambda:{'/api/resource','/api/demo/resource'})
    allowed_merchants:set[str]=field(default_factory=set)
    blocked_merchants:set[str]=field(default_factory=set)
    allowed_networks:set[str]=field(default_factory=set)
    allowed_assets:set[str]=field(default_factory=set)
    unknown_service_action:str='block' # review|block|allow
    max_frequency:int=100
    max_execution_cost:int=100_000
    risk_enforcement_mode:str='advisory'
    risk_hold_threshold:int=60
    risk_block_threshold:int=85
    ai_risk_weight:float=0.25
    require_independent_settlement_verification:bool=False
    fail_closed_on_verification_unavailable:bool=True
    def as_dict(self): return {'max_amount':self.max_amount,'daily_limit':self.daily_limit,'monthly_limit':self.monthly_limit,'approval_threshold':self.approval_threshold,'allowed_paths':sorted(self.allowed_paths),'allowed_merchants':sorted(self.allowed_merchants),'blocked_merchants':sorted(self.blocked_merchants),'allowed_networks':sorted(self.allowed_networks),'allowed_assets':sorted(self.allowed_assets),'unknown_service_action':self.unknown_service_action,'max_frequency':self.max_frequency,'max_execution_cost':self.max_execution_cost,'risk_enforcement_mode':self.risk_enforcement_mode,'risk_hold_threshold':self.risk_hold_threshold,'risk_block_threshold':self.risk_block_threshold,'ai_risk_weight':self.ai_risk_weight,'require_independent_settlement_verification':self.require_independent_settlement_verification,'fail_closed_on_verification_unavailable':self.fail_closed_on_verification_unavailable}

def check_policy(payload,request,policy,spent_today=0,spent_month=0,frequency=0):
    try: amount=int(payload.amount)
    except (ValueError,TypeError): return False,'invalid amount'
    if amount<0:return False,'negative amount'
    if amount>policy.max_amount:return False,'amount exceeds policy'
    if spent_today+amount>policy.daily_limit:return False,'daily spending limit exceeded'
    if spent_month+amount>policy.monthly_limit:return False,'monthly spending limit exceeded'
    if frequency>=policy.max_frequency:return False,'transaction frequency limit exceeded'
    if request.path not in policy.allowed_paths:return False,'endpoint not allowed'
    if request.merchant in policy.blocked_merchants:return False,'merchant blocked'
    if policy.allowed_merchants and request.merchant not in policy.allowed_merchants:
        if policy.unknown_service_action == 'allow': return True,'unknown merchant allowed by policy'
        if policy.unknown_service_action == 'review': return True,'review: unknown merchant'
        return False,'merchant not allowed'
    if policy.allowed_networks and payload.network not in policy.allowed_networks:return False,'network not allowed'
    if policy.allowed_assets and payload.asset not in policy.allowed_assets:return False,'asset not allowed'
    return True,'policy passed'

from __future__ import annotations
import time
from .atomicity import AtomicityGuard
from .binding import check_context_binding,binding_fingerprint
from .execution import ExecutionPolicy,check_execution_cost
from .freshness import check_freshness,check_payload_validity_window
from .ledger import ThreatLedger
from .policy import Policy,check_policy
from .settlement import verify_settlement_integrity
from .settlement_verify import SettlementAuthorisation
from .risk.engine import assess
from .risk.ai import AIRiskUnavailable, configured_provider
class AegisGateway:
    def __init__(self,adapter,policy=None,execution_policy=None,ledger=None,atomicity=None,store=None,reputation=None,settlement_verifier=None,ai_provider=None):self.adapter=adapter;self.policy=policy or Policy();self.execution_policy=execution_policy or ExecutionPolicy(self.policy.max_execution_cost);self.ledger=ledger or ThreatLedger();self.atomicity=atomicity or AtomicityGuard(store);self.store=store;self.reputation=reputation;self.settlement_verifier=settlement_verifier;self.ai_provider=ai_provider or configured_provider()
    def _block(self,checks,fp,reason,event='blocked',risk=None):
        eid=self.ledger.record(event,{'reason':reason,'fingerprint':fp,'checks':checks,'risk_score':risk.score if risk else 0,'risk_level':risk.level if risk else 'HIGH'});self.store and self.store.event(event,{'reason':reason,'fingerprint':fp,'checks':checks,'risk_score':risk.score if risk else 0,'risk_level':risk.level if risk else 'HIGH'});return {'decision':'BLOCK','reason':reason,'checks':checks,'fingerprint':fp,'event_id':eid,'risk_score':risk.score if risk else 0,'risk_level':risk.level if risk else 'HIGH','review_required':False}
    def inspect(self,payload,requirements,request,issued_at,estimated_cost=0,now=None,human_approved=False,already_reserved=False):
        checks={};fp=binding_fingerprint(payload,requirements,request)
        if self.store and payload.idempotency_key and not human_approved:
            prior=self.store.get_idempotency(payload.idempotency_key)
            if prior and prior['fingerprint']!=fp:return self._block(checks,fp,'idempotency key reused for a different payment','idempotency_mismatch')
            if prior:return self._block(checks,fp,'duplicate idempotent payment','idempotency_replay')
        ok,reason=check_context_binding(payload,requirements,request);checks['context_binding']='PASS' if ok else f'BLOCK: {reason}'
        if not ok:return self._block(checks,fp,'context mismatch','context_mismatch')
        ok,reason=check_freshness(requirements,issued_at,now);checks['freshness']='PASS' if ok else f'BLOCK: {reason}'
        if not ok:return self._block(checks,fp,reason,'stale_request')
        ok,reason=check_payload_validity_window(payload,now);checks['payload_validity']='PASS' if ok else f'BLOCK: {reason}'
        if not ok:return self._block(checks,fp,reason,'authorization_expired')
        current=time.time() if now is None else now;tm=time.localtime(current);day_start=time.mktime((tm.tm_year,tm.tm_mon,tm.tm_mday,0,0,0,0,0,0));month_start=time.mktime((tm.tm_year,tm.tm_mon,1,0,0,0,0,0,0));spent_today=self.store.spend_since(day_start) if self.store else 0;spent_month=self.store.spend_since(month_start) if self.store else 0;freq=self.store.frequency_since(day_start) if self.store else 0
        ok,reason=check_policy(payload,request,self.policy,spent_today,spent_month,freq);review=reason.startswith('review:');checks['policy']='PASS' if ok and not review else ('REVIEW: '+reason if review else f'BLOCK: {reason}')
        if not ok:return self._block(checks,fp,reason,'policy_violation')
        ai_result=None
        if self.ai_provider:
            try: ai_result=self.ai_provider.assess(payload,request,{'reputation': self.reputation.score(request.merchant) if self.reputation else None})
            except AIRiskUnavailable as e:
                checks['ai']='UNAVAILABLE'
                if getattr(self.policy,'risk_enforcement_mode','advisory')=='enforced' and getattr(__import__('os').environ,'get')('AEGIS_AI_RISK_REQUIRED','false').lower() in {'1','true','yes','on'}:
                    return self._block(checks,fp,'required AI risk service unavailable','ai_unavailable')
        risk=assess(payload,request,self.policy,self.reputation.score(request.merchant) if self.reputation else None,ai_result);checks['risk']=f'{risk.level}:{risk.score}';checks['risk_deterministic']=str(risk.deterministic_score);checks['risk_ai']=str(risk.ai_score) if risk.ai_score is not None else 'NONE'
        if getattr(self.policy,'risk_enforcement_mode','advisory')=='enforced' and not human_approved:
            if risk.score>=getattr(self.policy,'risk_block_threshold',85): return self._block(checks,fp,f'risk score {risk.score} meets block threshold','risk_block',risk)
            if risk.score>=getattr(self.policy,'risk_hold_threshold',60):
                eid=self.ledger.record('review_required',{'fingerprint':fp,'risk':risk.__dict__,'reason':'risk threshold'});self.store and self.store.event('review_required',{'fingerprint':fp,'risk':risk.__dict__,'reason':'risk threshold'});return {'decision':'REVIEW','reason':'risk score requires review','checks':checks,'fingerprint':fp,'event_id':eid,'risk_score':risk.score,'risk_level':risk.level,'review_required':True}
        ok,reason=check_execution_cost(estimated_cost,self.execution_policy);checks['execution']='PASS' if ok else f'BLOCK: {reason}'
        if not ok:return self._block(checks,fp,reason,'execution_limit_violation',risk)
        if not already_reserved:
            reserved,reason=self.atomicity.reserve(payload.nonce,fp);checks['atomicity']='PASS' if reserved else f'BLOCK: {reason}'
            if not reserved:return self._block(checks,fp,reason,'replay_attempt',risk)
        else:checks['atomicity']='PASS: existing review reservation'
        try:
            valid,vr=self.adapter.verify(payload,requirements);checks['verification']='PASS' if valid else f'BLOCK: {vr}'
            if not valid:return self._block(checks,fp,vr,'verification_failure',risk)
            if (review or int(payload.amount)>self.policy.approval_threshold) and not human_approved:
                eid=self.ledger.record('review_required',{'fingerprint':fp,'risk':risk.__dict__});self.store and self.store.event('review_required',{'fingerprint':fp,'risk':risk.__dict__});return {'decision':'REVIEW','reason':'human approval required by policy','checks':checks,'fingerprint':fp,'event_id':eid,'risk_score':risk.score,'risk_level':risk.level,'review_required':True}
            result=self.adapter.settle(payload,requirements);checks['settlement']='PASS' if result.success else f'BLOCK: {result.reason or "settlement failed"}'
            if not result.success:return self._block(checks,fp,'settlement failed','settlement_failure',risk)
            ok,reason=verify_settlement_integrity(payload,requirements,result);checks['settlement_integrity']='PASS' if ok else f'BLOCK: {reason}'
            if not ok:return self._block(checks,fp,reason,'settlement_mismatch',risk)
            if self.policy.require_independent_settlement_verification:
                if not self.settlement_verifier:
                    if self.policy.fail_closed_on_verification_unavailable:
                        self.atomicity.commit(payload.nonce);eid=self.ledger.record('settlement_unverified',{'fingerprint':fp,'tx_hash':result.tx_hash,'reason':'independent verifier unavailable','risk':risk.__dict__});return {'decision':'REVIEW','reason':'independent settlement verification unavailable','checks':checks|{'independent_settlement':'UNAVAILABLE'},'fingerprint':fp,'event_id':eid,'risk_score':risk.score,'risk_level':risk.level,'review_required':True,'settlement':result.model_dump()}
                auth=SettlementAuthorisation(payload.payer,payload.pay_to,payload.amount,payload.asset,payload.network,fp)
                verification=self.settlement_verifier.verify(auth,result.tx_hash or '')
                checks['independent_settlement']=verification.mode.upper()
                if not verification.verified:
                    self.atomicity.commit(payload.nonce);eid=self.ledger.record('settlement_unverified',{'fingerprint':fp,'tx_hash':result.tx_hash,'reason':verification.reason,'risk':risk.__dict__});return {'decision':'REVIEW','reason':verification.reason,'checks':checks,'fingerprint':fp,'event_id':eid,'risk_score':risk.score,'risk_level':risk.level,'review_required':True,'settlement':result.model_dump()}
            else: checks['independent_settlement']='NOT_REQUIRED'
            if self.store:
                self.store.event('allowed_transaction',{'amount':int(payload.amount),'fingerprint':fp,'tx_hash':result.tx_hash,'merchant':request.merchant,'network':payload.network,'asset':payload.asset})
                if payload.idempotency_key:self.store.put_idempotency(payload.idempotency_key,fp,'ALLOW')
            self.atomicity.commit(payload.nonce);eid=self.ledger.record('allowed_transaction',{'fingerprint':fp,'tx_hash':result.tx_hash,'risk':risk.__dict__});return {'decision':'ALLOW','reason':'security checks passed and settlement succeeded','checks':checks,'fingerprint':fp,'event_id':eid,'risk_score':risk.score,'risk_level':risk.level,'review_required':False,'settlement':result.model_dump()}
        finally:self.atomicity.release(payload.nonce)
    def approve(self,payload,requirements,request,issued_at,estimated_cost=0,now=None):return self.inspect(payload,requirements,request,issued_at,estimated_cost,now,True,True)

from __future__ import annotations
import base64,json,time,uuid,os,hmac,hashlib,secrets
from pathlib import Path
from typing import Any
import httpx
from fastapi import FastAPI,HTTPException,Header,Request
from fastapi.responses import FileResponse,JSONResponse
from pydantic import BaseModel,Field,ConfigDict
from .atomicity import AtomicityGuard
from .config.settings import Settings
from .gateway import AegisGateway
from .identity import NodeIdentity
from .ledger import ThreatLedger
from .models import PaymentPayload,PaymentRequirements,RequestContext
from .network.peer import PeerProtocol
from .network.reputation import ReputationNetwork
from .network.privacy import PrivateReputation
from .policy import Policy
from .storage.sqlite import SQLiteStore
from .threats.reports import ThreatSigner,ThreatReport,PeerEnvelope,make_report
from .x402_adapter import MockX402Adapter,X402FacilitatorAdapter
from .network.consensus import BFTThreatConsensus
from .anchoring import LocalAnchorBackend,EVMAnchorBackend,merkle_root,merkle_proof,verify_proof
from .settlement_verify import EVMSettlementVerifier,SettlementAuthorisation
from .secrets import validate_production
from .security.auth import Role, require_role
settings=Settings()
if settings.environment.lower()=='production':
    if not any(os.getenv(k,'') for k in ('AEGIS_ADMIN_TOKEN','AEGIS_SECURITY_TOKEN','AEGIS_POLICY_TOKEN','AEGIS_AUDITOR_TOKEN','AEGIS_OPERATOR_TOKEN','AEGIS_ADMIN_PASSWORD')):
        raise RuntimeError('production requires administrator credentials')
    if os.getenv('AEGIS_ADMIN_PASSWORD') and not os.getenv('AEGIS_ADMIN_SESSION_SECRET'):
        raise RuntimeError('production requires AEGIS_ADMIN_SESSION_SECRET when AEGIS_ADMIN_PASSWORD is set')
    if settings.ai_risk_required and not settings.ai_risk_url:
        raise RuntimeError('production requires AEGIS_AI_RISK_URL when AEGIS_AI_RISK_REQUIRED=true')
    if settings.anchor_backend=='evm' and not (settings.rpc_url and settings.anchor_contract and os.getenv('AEGIS_ANCHOR_PRIVATE_KEY','')):
        raise RuntimeError('production EVM anchoring requires RPC, contract and dedicated signing key')
store=SQLiteStore(settings.db_path);ledger=ThreatLedger(settings.ledger_path);policy=Policy();atomicity=AtomicityGuard(store);identity=NodeIdentity(settings.node_id,settings.node_signing_key or None,settings.node_key_path);network=ReputationNetwork(store,settings.node_id);peers=PeerProtocol(store,identity,settings.max_clock_skew_seconds,settings.max_peer_reports_per_minute);private_reputation=PrivateReputation(settings.node_signing_key or identity.public_key);signer=ThreatSigner(identity);adapter=X402FacilitatorAdapter(settings.facilitator_url,settings.x402_version) if settings.adapter=='facilitator' else MockX402Adapter();consensus=BFTThreatConsensus(identity,store)
anchor_backend=EVMAnchorBackend(settings.rpc_url,settings.anchor_contract,os.getenv('AEGIS_ANCHOR_PRIVATE_KEY','')) if settings.anchor_backend=='evm' else LocalAnchorBackend()
settlement_verifier=EVMSettlementVerifier(settings.rpc_url,settings.settlement_confirmation_depth) if settings.rpc_url else None
gateway=AegisGateway(adapter,policy=policy,ledger=ledger,atomicity=atomicity,store=store,reputation=network,settlement_verifier=settlement_verifier)
app=FastAPI(title='Aegis402',version='1.0.0')

_MUTATING_ADMIN={('/api/config','PUT'):Role.POLICY,('/api/policies','POST'):Role.POLICY,('/api/policies','PUT'):Role.POLICY,('/api/policies','DELETE'):Role.POLICY,('/api/payment/approve','POST'):Role.OPERATOR,('/api/payment/deny','POST'):Role.OPERATOR,('/api/threats','POST'):Role.SECURITY,('/api/threats/broadcast','POST'):Role.SECURITY,('/api/network/consensus/propose','POST'):Role.SECURITY,('/api/network/consensus/verify','POST'):Role.SECURITY,('/api/network/consensus/commit-check','POST'):Role.SECURITY,('/api/anchors','POST'):Role.OPERATOR,('/api/anchors/proof','POST'):Role.AUDITOR,('/api/anchors/verify','POST'):Role.AUDITOR,('/api/node/rotate-key','POST'):Role.SECURITY,('/api/peers','POST'):Role.SECURITY,('/api/peers/revoke','POST'):Role.SECURITY}
_SENSITIVE_GET={'/api/config':Role.AUDITOR,'/api/events':Role.AUDITOR,'/api/ledger':Role.AUDITOR,'/api/ledger/verify':Role.AUDITOR,'/api/threats':Role.AUDITOR,'/api/network/consensus':Role.AUDITOR,'/api/reputation':Role.AUDITOR,'/api/reputation/private':Role.AUDITOR,'/api/peers':Role.AUDITOR,'/api/review':Role.OPERATOR,'/api/node/identity':Role.AUDITOR,'/api/anchors':Role.AUDITOR}

def _required_role(path,method):
    if (path,method) in _MUTATING_ADMIN:return _MUTATING_ADMIN[(path,method)]
    if method=='POST' and path.startswith('/api/policies/'):return Role.POLICY
    if method=='PUT' and path.startswith('/api/policies/'):return Role.POLICY
    if method=='DELETE' and path.startswith('/api/policies/'):return Role.POLICY
    if method=='POST' and path.startswith('/api/peers/') and path.endswith('/revoke'):return Role.SECURITY
    if method=='GET' and path in _SENSITIVE_GET:return _SENSITIVE_GET[path]
    if method=='GET' and path.startswith('/api/reputation/') and path.endswith('/explain'):return Role.AUDITOR
    if method=='GET' and path.startswith('/api/threats/') and path!='/api/threats/request':return Role.AUDITOR
    return None


SESSION_TTL = 8 * 60 * 60

def _session_token():
    secret=os.getenv('AEGIS_ADMIN_SESSION_SECRET','')
    if not secret: return ''
    issued=int(time.time())
    body=f"admin:{issued}:{secrets.token_urlsafe(12)}"
    sig=hmac.new(secret.encode(),body.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}:{sig}".encode()).decode().rstrip('=')

def _valid_session(token):
    secret=os.getenv('AEGIS_ADMIN_SESSION_SECRET','')
    if not secret or not token: return False
    try:
        raw=base64.urlsafe_b64decode(token+'='*(-len(token)%4)).decode()
        role,issued,nonce,sig=raw.split(':',3)
        if role!='admin' or int(time.time())-int(issued)>SESSION_TTL: return False
        body=f"{role}:{issued}:{nonce}"
        return hmac.compare_digest(sig,hmac.new(secret.encode(),body.encode(),hashlib.sha256).hexdigest())
    except Exception:
        return False

class AdminLogin(BaseModel):
    password:str

@app.post('/api/admin/login')
def admin_login(body:AdminLogin):
    expected=os.getenv('AEGIS_ADMIN_PASSWORD','')
    if not expected or not hmac.compare_digest(body.password,expected):
        raise HTTPException(401,'invalid administrator credentials')
    token=_session_token()
    if not token: raise HTTPException(503,'administrator session secret is not configured')
    return {'authenticated':True,'role':'admin','token':token,'expires_in':SESSION_TTL}

@app.get('/api/admin/session')
def admin_session(request:Request):
    auth=request.headers.get('Authorization','')
    token=auth[7:].strip() if auth.lower().startswith('bearer ') else ''
    return {'authenticated':_valid_session(token)}

@app.middleware('http')
async def security_middleware(request:Request, call_next):
    role=_required_role(request.url.path,request.method)
    if role:
        env=os.getenv('AEGIS_ENV','development').lower(); required=os.getenv('AEGIS_REQUIRE_ADMIN_AUTH','true' if env=='production' else 'false').lower() in {'1','true','yes','on'}
        if required:
            auth=request.headers.get('Authorization','')
            if not auth.lower().startswith('bearer '): return JSONResponse(status_code=401,content={'detail':'administrator authentication required'})
            supplied=auth[7:].strip(); names={Role.ADMIN:'AEGIS_ADMIN_TOKEN',Role.SECURITY:'AEGIS_SECURITY_TOKEN',Role.POLICY:'AEGIS_POLICY_TOKEN',Role.AUDITOR:'AEGIS_AUDITOR_TOKEN',Role.OPERATOR:'AEGIS_OPERATOR_TOKEN'}
            allowed=[]
            for r in (role,Role.ADMIN):
                t=os.getenv(names[r],'')
                if t: allowed.append(t)
            valid_static=any(hmac.compare_digest(supplied,t) for t in allowed)
            valid_session=_valid_session(supplied)
            if not (valid_static or valid_session): return JSONResponse(status_code=403,content={'detail':'insufficient administrator privileges'})
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY';response.headers['Referrer-Policy']='no-referrer';response.headers['Cache-Control']='no-store' if request.url.path.startswith('/api/') else 'no-cache'
    return response


def capability_status():
    try: adapter_status=adapter.status(); adapter_mode=adapter_status.get('mode','UNKNOWN')
    except Exception: adapter_status={'mode':'UNAVAILABLE'}; adapter_mode='UNAVAILABLE'
    return {'environment':settings.environment,'admin_auth_required':settings.require_admin_auth or os.getenv('AEGIS_REQUIRE_ADMIN_AUTH','').lower() in {'1','true','yes','on'},'risk':{'deterministic_core':True,'ai_configured':bool(settings.ai_risk_url),'ai_required':settings.ai_risk_required,'enforcement':policy.risk_enforcement_mode,'hold_threshold':policy.risk_hold_threshold,'block_threshold':policy.risk_block_threshold,'ai_weight':policy.ai_risk_weight},'x402':{'adapter_mode':adapter_mode,'facilitator_configured':settings.adapter=='facilitator'},'settlement':{'independent_verifier_configured':settlement_verifier is not None,'required':policy.require_independent_settlement_verification,'confirmation_depth':settings.settlement_confirmation_depth},'anchoring':{'backend':settings.anchor_backend,'evm_configured':settings.anchor_backend=='evm' and bool(settings.rpc_url and settings.anchor_contract)},'hsm':{'provider':'external-boundary','hardware_backed':False},'privacy':'pseudonymisation/minimisation'}

class ConfigUpdate(BaseModel):
    model_config=ConfigDict(extra='forbid')
    max_amount:int|None=None;daily_limit:int|None=None;monthly_limit:int|None=None;approval_threshold:int|None=None;allowed_merchants:list[str]|None=None;blocked_merchants:list[str]|None=None;allowed_networks:list[str]|None=None;allowed_assets:list[str]|None=None;allowed_paths:list[str]|None=None;unknown_service_action:str|None=None;max_frequency:int|None=None;max_execution_cost:int|None=None;risk_enforcement_mode:str|None=None;risk_hold_threshold:int|None=None;risk_block_threshold:int|None=None;ai_risk_weight:float|None=None;require_independent_settlement_verification:bool|None=None;fail_closed_on_verification_unavailable:bool|None=None
class EvaluateRequest(BaseModel):payload:PaymentPayload;requirements:PaymentRequirements;request:RequestContext;issued_at:float|None=None;estimated_cost:int=0
class DecisionAction(BaseModel):fingerprint:str
class ThreatIn(BaseModel):threat_type:str;target:str;evidence_reference:str='';confidence:float=Field(.5,ge=0,le=1);severity:str='medium';expires_at:float|None=None;indicators:list[str]=Field(default_factory=list);context:dict[str,Any]=Field(default_factory=dict)
class PeerIn(BaseModel):node_id:str;endpoint:str;public_identity:str;trust:float=Field(.2,ge=0,le=1);bootstrap:bool=False;capabilities:list[str]=Field(default_factory=list)
class PeerEnvelopeIn(BaseModel):envelope:dict[str,Any]
def policy_apply(data):
    for k,v in data.model_dump(exclude_none=True).items():
        if k=='allowed_merchants':policy.allowed_merchants=set(v)
        elif k=='blocked_merchants':policy.blocked_merchants=set(v)
        elif k=='allowed_networks':policy.allowed_networks=set(v)
        elif k=='allowed_assets':policy.allowed_assets=set(v)
        elif k=='allowed_paths':policy.allowed_paths=set(v)
        elif k=='unknown_service_action' and v not in {'allow','block','review'}:raise HTTPException(400,'unknown_service_action must be allow, block or review')
        else:setattr(policy,k,v)
    store.set_config('policy',policy.as_dict());return policy.as_dict()
def x402_to_local(payment,req):
    accepted=payment.get('accepted') or req;auth=(payment.get('payload') or {}).get('authorization',{});return PaymentPayload(payer=auth.get('from',''),resource=(payment.get('resource') or {}).get('url',req.get('resource','')),amount=str(accepted.get('amount','')),pay_to=accepted.get('payTo',accepted.get('pay_to','')),nonce=str(auth.get('nonce','')),signature=(payment.get('payload') or {}).get('signature',''),scheme=accepted.get('scheme','exact'),network=accepted.get('network',''),asset=accepted.get('asset',''),valid_after=int(auth['validAfter']) if auth.get('validAfter') is not None else None,valid_before=int(auth['validBefore']) if auth.get('validBefore') is not None else None,metadata={'x402':payment})
def local_requirements(req):return PaymentRequirements(scheme=req.get('scheme','exact'),network=req.get('network',''),asset=req.get('asset',''),amount=str(req.get('amount','')),pay_to=req.get('payTo',req.get('pay_to','')),resource=req.get('resource',''),max_timeout_seconds=int(req.get('maxTimeoutSeconds',req.get('max_timeout_seconds',300))),extra=req.get('extra',{}))
@app.get('/',include_in_schema=False)
def root():return {'name':'Aegis402','version':'1.0.0','status':'payment security agent','dashboard':'/dashboard','engineering':'/engineering','admin':'/admin','demo':'/demo','shop':'/shop','explainer':'/explainer','docs':'/docs'}
@app.get('/dashboard',include_in_schema=False)
def dashboard():return FileResponse(Path(__file__).resolve().parent.parent/'dashboardwt'/'dashboard.html')
@app.get('/dashboard-old',include_in_schema=False)
@app.get('/index2', include_in_schema=False)
def index2():
    return FileResponse(
        Path(_file_).resolve().parent.parent / 'dashboardwt' / 'index2.html'
    )
def dashboard_old():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'index.html')
@app.get('/dashboardwt',include_in_schema=False)
def dashboardwt():return FileResponse(Path(__file__).resolve().parent.parent/'dashboardwt'/'dashboard.html')
@app.get('/engineering',include_in_schema=False)
def engineering():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'engineering.html')
@app.get('/admin',include_in_schema=False)
def admin_page():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'admin.html')
@app.get('/demo',include_in_schema=False)
def demo_page():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'demo.html')
@app.get('/explainer',include_in_schema=False)
def explainer():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'explainer.html')
@app.get('/shop',include_in_schema=False)
def shop_page():return FileResponse(Path(__file__).resolve().parent.parent/'dashboard'/'shop.html')







@app.get('/api/engineering/overview')
def engineering_overview():
    # Public read-only engineering telemetry. Raw ledger, peer administration and private reputation remain protected.
    events=store.events(40)
    safe_events=[{'event_type':e.get('event_type'),'created_at':e.get('created_at'),'fingerprint':str(e.get('fingerprint',''))[:16],'risk_score':e.get('risk_score'),'risk_level':e.get('risk_level')} for e in events]
    safe_threats=[{'report_id':t.get('report_id'),'threat_type':t.get('threat_type'),'severity':t.get('severity'),'confidence':t.get('confidence'),'reporter_node':t.get('reporter_node'),'expires_at':t.get('expires_at')} for t in store.threats()]
    return {'node':identity.metadata(),'capabilities':capability_status(),'distributed_network':{'peer_count':len(store.peers()),'independent_node':True},'ledger':ledger.verify_chain(),'events':safe_events,'threats':safe_threats}

@app.get('/api/status')
def status():
    try:ast=adapter.status()
    except Exception as e:ast={'mode':'UNAVAILABLE','error':str(e)}
    return {'name':'Aegis402','version':'1.0.0','protection':'active','adapter':ast,'node':identity.metadata(),'ledger':ledger.verify_chain(),'storage':'sqlite-local','capabilities':capability_status(),'distributed_network':{'independent_node':True,'central_server_required':False,'peer_count':len(store.peers()),'consensus':{'members':len(consensus.membership()),'quorum':consensus.config.quorum(len(consensus.membership()))}}}
@app.get('/api/capabilities')
def capabilities(): return capability_status()

@app.get('/api/config')
def get_config():
    try: ast=adapter.status()
    except Exception as e: ast={'mode':'UNAVAILABLE','error':str(e)}
    return policy.as_dict()|{'node_id':settings.node_id,'adapter':ast}
@app.put('/api/config')
def put_config(data:ConfigUpdate):return policy_apply(data)
@app.get('/api/policies')
def policies():return store.policies()
@app.post('/api/policies')
def add_policy(data:dict):pid=data.pop('id',str(uuid.uuid4()));store.put_policy(pid,data);return {'id':pid,**data}
@app.put('/api/policies/{pid}')
def edit_policy(pid,data:dict):store.put_policy(pid,data);return {'id':pid,**data}
@app.delete('/api/policies/{pid}')
def del_policy(pid):store.delete_policy(pid);return {'deleted':pid}
@app.post('/api/payment/evaluate')
def evaluate(body:EvaluateRequest):
    result=gateway.inspect(body.payload,body.requirements,body.request,body.issued_at or time.time(),body.estimated_cost)
    if result['decision']=='REVIEW':store.pending_put(result['fingerprint'],{'request':body.model_dump(),'reason':result['reason'],'risk_score':result['risk_score'],'risk_level':result['risk_level'],'checks':result['checks']})
    return result
@app.post('/api/x402/evaluate')
def x402_evaluate(body:EvaluateRequest):return evaluate(body)
@app.post('/api/payment/approve')
def approve(body:DecisionAction):
    pending=store.pending_get(body.fingerprint)
    if not pending:raise HTTPException(404,'review request not found')
    p=EvaluateRequest.model_validate(pending['request']);result=gateway.approve(p.payload,p.requirements,p.request,p.issued_at or time.time(),p.estimated_cost)
    if result['decision']!='REVIEW':store.pending_delete(body.fingerprint)
    return result
@app.post('/api/payment/deny')
def deny(body:DecisionAction):
    pending=store.pending_get(body.fingerprint)
    if not pending:raise HTTPException(404,'review request not found')
    store.pending_delete(body.fingerprint);atomicity.release(pending['request']['payload']['nonce']);eid=ledger.record('human_denied',{'fingerprint':body.fingerprint});store.event('human_denied',{'fingerprint':body.fingerprint});return {'decision':'BLOCK','reason':'consumer denied payment','event_id':eid}
@app.get('/api/events')
def events():return store.events(200)
@app.get('/api/ledger')
def ledger_events():return [json.loads(x) for x in ledger.path.read_text().splitlines() if x.strip()][-200:] if ledger.path.exists() else []
@app.get('/api/ledger/verify')
def verify_ledger():ok,broken,count=ledger.verify_chain();return {'valid':ok,'broken_at':broken,'event_count':count}
@app.get('/api/threats')
def threats():return store.threats()
@app.post('/api/threats')
def create_threat(data:ThreatIn):
    r=make_report(settings.node_id,data.threat_type,data.target,data.evidence_reference,data.confidence,data.severity,data.expires_at,data.indicators,data.context);signer.sign(r);network.publish(r);ledger.record('threat_report_created',{'report_id':r.report_id,'threat_type':r.threat_type});return r.model_dump(mode='json')
@app.get('/api/threats/{report_id}')
def threat_by_id(report_id):
    r=next((x for x in store.threats() if x.get('report_id')==report_id),None)
    if not r:raise HTTPException(404,'threat report not found')
    return r
@app.post('/api/threats/request')
def request_threat(body:PeerEnvelopeIn):
    if len(json.dumps(body.envelope,separators=(',',':')).encode()) > settings.max_peer_report_bytes: raise HTTPException(413,'peer message exceeds configured size limit')
    try: env=PeerEnvelope(**body.envelope); ok,reason=peers.verify_envelope(env)
    except Exception as e: raise HTTPException(400,f'malformed peer envelope: {e}')
    if not ok: raise HTTPException(403,reason)
    if env.report.get('request')!='report': raise HTTPException(400,'unsupported peer request')
    report=next((r for r in store.threats() if r.get('report_id')==env.report.get('report_id')),None)
    if not report: raise HTTPException(404,'threat report not found')
    return {'report':report}

@app.post('/api/threats/ingest')
def ingest_threat(body:PeerEnvelopeIn):
    if len(json.dumps(body.envelope,separators=(',',':')).encode()) > settings.max_peer_report_bytes: raise HTTPException(413,'peer message exceeds configured size limit')
    try:env=PeerEnvelope(**body.envelope);ok,reason=peers.verify_envelope(env)
    except Exception as e:raise HTTPException(400,f'malformed peer envelope: {e}')
    if not ok:raise HTTPException(403,reason)
    try:r=ThreatReport(**env.report)
    except Exception as e:raise HTTPException(400,f'malformed threat report: {e}')
    if r.expires_at is not None and r.expires_at<time.time():return {'accepted':False,'reason':'expired report'}
    issuer=store.get_peer(r.reporter_node) if r.reporter_node!=settings.node_id else {'public_identity':identity.public_key,'trusted':True,'revoked':False}
    if not issuer or issuer.get('revoked') or not issuer.get('trusted'):raise HTTPException(403,'report issuer is not trusted')
    if not signer.verify(r,issuer['public_identity']):raise HTTPException(403,'invalid report signature')
    accepted,why=network.ingest(r);forwarded=_forward_report(r,env.sender_node,env.ttl-1) if accepted else [];ledger.record('threat_report_ingested',{'report_id':r.report_id,'reporter_node':r.reporter_node,'accepted':accepted,'reason':why,'forwarded':len(forwarded)});return {'accepted':accepted,'reason':why,'report_id':r.report_id,'forwarded':forwarded}
def _forward_report(r,exclude=None,ttl=2):
    if ttl<=0:return []
    out=[]
    for p in store.peers():
        if p['node_id'] in {settings.node_id,exclude} or p.get('revoked') or not p.get('trusted'):continue
        env=peers.make_envelope(r,ttl)
        try:
            resp=httpx.post(p['endpoint'].rstrip('/')+'/api/threats/ingest',json={'envelope':env.model_dump(mode='json')},timeout=settings.peer_timeout_seconds);out.append({'node_id':p['node_id'],'accepted':resp.status_code==200,'status_code':resp.status_code})
        except Exception as e:out.append({'node_id':p['node_id'],'accepted':False,'error':str(e)})
    return out

@app.get('/api/network/consensus')
def consensus_status():
    members=consensus.membership()
    return {"epoch":consensus.config.epoch,"members":members,"fault_threshold":consensus.f(),
            "quorum":consensus.config.quorum(len(members)),"critical_payment_path":False}

class ConsensusProposal(BaseModel):
    state:dict[str,Any]; sequence:int=Field(ge=0)
@app.post('/api/network/consensus/propose')
def consensus_propose(body:ConsensusProposal):
    return consensus.proposal(body.state,body.sequence)
@app.post('/api/network/consensus/verify')
def consensus_verify(body:dict[str,Any]):
    ok,reason=consensus.verify(body); return {"valid":ok,"reason":reason}
@app.post('/api/network/consensus/commit-check')
def consensus_commit_check(body:dict[str,Any]):
    return {"committed":consensus.commit_rule(body.get("prepare_voters",[]),body.get("commit_voters",[])),
            "quorum":consensus.config.quorum(len(consensus.membership()))}

@app.get('/api/reputation/{target:path}/explain')
def reputation_explain(target): return network.explain(target)

@app.get('/api/anchors')
def anchors():
    return store.get_config("anchors",[])
class AnchorBatch(BaseModel):
    events:list[dict[str,Any]]
@app.post('/api/anchors')
def create_anchor(body:AnchorBatch):
    root=merkle_root(body.events); anchor=anchor_backend.anchor(root,{"event_count":len(body.events)})
    anchors=store.get_config("anchors",[]); anchors.append(anchor); store.set_config("anchors",anchors)
    return {"root":root,"anchor":anchor}
class MerkleProofRequest(BaseModel):
    events:list[dict[str,Any]]; index:int=Field(ge=0)
@app.post('/api/anchors/proof')
def create_merkle_proof(body:MerkleProofRequest):
    if body.index>=len(body.events): raise HTTPException(400,"index out of range")
    return {"root":merkle_root(body.events),"event":body.events[body.index],"proof":merkle_proof(body.events,body.index)}
@app.post('/api/anchors/verify')
def verify_merkle(body:dict[str,Any]):
    return {"valid":verify_proof(body["event"],body["proof"],body["root"])}

class SettlementVerifyRequest(BaseModel):
    rpc_url:str; transaction:str; payer:str; recipient:str; amount:str; asset:str; network:str; payment_fingerprint:str
    confirmation_depth:int=Field(2,ge=1,le=100)
@app.post('/api/settlement/verify')
def settlement_verify(body:SettlementVerifyRequest):
    auth=SettlementAuthorisation(body.payer,body.recipient,body.amount,body.asset,body.network,body.payment_fingerprint)
    return EVMSettlementVerifier(body.rpc_url,body.confirmation_depth).verify(auth,body.transaction).__dict__

@app.get('/api/node/identity')
def node_identity():return identity.metadata()
@app.post('/api/node/rotate-key')
def rotate_key():r=identity.rotate();ledger.record('node_key_rotated',{'old_public_key':r['old_public_key'],'new_public_key':r['new_public_key']});return identity.metadata()|r
@app.get('/api/reputation')
def reputation():return {'digest':network.digest(),'targets':store.reputations()}
@app.get('/api/reputation/private')
def private_reputation_view():return {'mode':'keyed-pseudonymisation','privacy_limitations':'Not differential privacy, MPC, ZK or anonymous reputation.','aggregate':private_reputation.aggregate(store.threats())}
@app.get('/api/peers')
def peer_list():return store.peers()
@app.post('/api/peers')
def peer(data:PeerIn,x_aegis_bootstrap_token:str|None=Header(default=None)):
    if settings.peer_bootstrap_token and x_aegis_bootstrap_token!=settings.peer_bootstrap_token:raise HTTPException(403,'bootstrap authentication failed')
    try:peers.register(data.node_id,data.endpoint,data.public_identity,data.trust,data.bootstrap,data.capabilities)
    except ValueError as e:raise HTTPException(409,str(e))
    ledger.record('peer_registered',{'node_id':data.node_id,'public_key':data.public_identity,'trusted':data.trust>0});return data.model_dump()
@app.post('/api/peers/{node_id}/revoke')
def revoke_peer(node_id):peers.revoke(node_id);ledger.record('peer_revoked',{'node_id':node_id});return {'revoked':node_id}
@app.post('/api/threats/broadcast')
def broadcast_threat(data:ThreatIn):
    r=make_report(settings.node_id,data.threat_type,data.target,data.evidence_reference,data.confidence,data.severity,data.expires_at,data.indicators,data.context);signer.sign(r);network.publish(r);return {'report':r.model_dump(mode='json'),'results':_forward_report(r,None,3)}
@app.get('/api/x402/status')
def x402_status():
    try:return adapter.status()
    except Exception as e:return {'mode':'UNAVAILABLE','error':str(e)}
@app.get('/api/review')
def review_queue():return store.pending_all()
def demo_requirement(resource):
    return {'scheme':'exact','network':settings.x402_network,'asset':settings.x402_asset or 'USDC','amount':str(settings.demo_price),'payTo':settings.demo_pay_to or '0x000000000000000000000000000000000000dEaD','maxTimeoutSeconds':300,'extra':{'name':'USD Coin','version':'2'},'resource':resource}

@app.get('/api/demo/cases')
def demo_cases():
    return {'mode':'LOCAL TEST','cases':['normal','cross-resource','replay','stale','expired-authorization','wrong-network','invalid-signature','cost','settlement-failure','nonce-race','distributed']}

@app.post('/api/demo/case')
def demo_case(body:dict):
    name=str(body.get('case','normal'))
    resource='http://demo.local/api/demo/resource'
    req=demo_requirement(resource)
    base=PaymentPayload(payer='0xDemoPayer',resource=resource,amount=req['amount'],pay_to=req['payTo'],nonce=uuid.uuid4().hex,signature='demo-signature',scheme='exact',network=req['network'],asset=req['asset'],valid_after=int(time.time())-10,valid_before=int(time.time())+300)
    if name=='cross-resource': base=base.model_copy(update={'resource':'http://other.local/resource'})
    if name=='replay': base=base.model_copy(update={'nonce':'demo-replay'})
    if name=='stale': req['issued_at']=time.time()-1000
    if name=='expired-authorization': base=base.model_copy(update={'valid_before':int(time.time())-1})
    if name=='wrong-network': base=base.model_copy(update={'network':'eip155:1'})
    if name=='invalid-signature': base=base.model_copy(update={'signature':'invalid'})
    if name=='cost': estimated=999999
    else: estimated=0
    if name=='settlement-failure': adapter.settlement_should_fail=True if isinstance(adapter,MockX402Adapter) else False
    ctx=RequestContext(method='GET',path='/api/demo/resource',resource=resource,merchant=req['payTo'],request_id=str(uuid.uuid4()))
    try:
        result=gateway.inspect(base,local_requirements(req),ctx,req.get('issued_at',time.time()),estimated)
    finally:
        if isinstance(adapter,MockX402Adapter): adapter.settlement_should_fail=False
    if name=='nonce-race':
        import concurrent.futures
        def one(i):
            p=base.model_copy(update={'nonce':'race-single'})
            return gateway.inspect(p,local_requirements(req),ctx,time.time())
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex: results=list(ex.map(one,range(20)))
        allowed=sum(x.get('decision')=='ALLOW' for x in results); blocked=sum(x.get('decision')!='ALLOW' for x in results)
        result={'decision':'ALLOW' if allowed==1 else 'BLOCK','reason':f'{allowed} allowed, {blocked} blocked across 20 concurrent attempts','checks':{'atomicity':f'PASS: {allowed} settlement path' if allowed==1 else 'FAIL'},'risk_score':0,'risk_level':'LOW','event_id':results[0].get('event_id','')}
    return {'name':name,'mode':'LOCAL TEST','result':result}

@app.get('/api/live/shop')
def live_shop_get(request:Request):
    resource=str(request.url).split('?')[0]
    req=demo_requirement(resource)
    if not settings.demo_pay_to:
        return JSONResponse(status_code=503,content={'error':'AEGIS_DEMO_PAY_TO is not configured for a live transaction.'})
    return JSONResponse(status_code=402,content={'x402Version':2,'error':'PAYMENT_REQUIRED','resource':{'url':resource,'description':'Aegis protected demonstration purchase','mimeType':'application/json'},'accepts':[req],'extensions':{}},headers={'PAYMENT-REQUIRED':base64.b64encode(json.dumps({'x402Version':2,'error':'PAYMENT_REQUIRED','resource':{'url':resource,'description':'Aegis protected demonstration purchase','mimeType':'application/json'},'accepts':[req],'extensions':{}},separators=(',',':')).encode()).decode()})

@app.post('/api/live/shop')
def live_shop_post(request:Request):
    token=request.headers.get('PAYMENT-SIGNATURE') or request.headers.get('X-PAYMENT')
    resource=str(request.url).split('?')[0]
    req=demo_requirement(resource)
    if not token: return live_shop_get(request)
    try: payment=json.loads(base64.b64decode(token).decode())
    except Exception: raise HTTPException(400,'invalid PAYMENT-SIGNATURE encoding')
    if payment.get('x402Version')!=2: raise HTTPException(400,'x402 v2 payment required')
    p=x402_to_local(payment,req)
    ctx=RequestContext(method='POST',path='/api/live/shop',resource=resource,merchant=req['payTo'],request_id=request.headers.get('X-Request-ID',str(uuid.uuid4())))
    result=gateway.inspect(p,local_requirements(req),ctx,time.time(),0)
    if result['decision']=='REVIEW':
        store.pending_put(result['fingerprint'],{'request':{'payload':p.model_dump(),'requirements':local_requirements(req).model_dump(),'request':ctx.model_dump(),'issued_at':time.time(),'estimated_cost':0},'reason':result['reason'],'risk_score':result['risk_score'],'risk_level':result['risk_level'],'checks':result['checks']})
        return JSONResponse(status_code=202,content={'aegis':result,'message':'Human approval required. Open the review queue.'})
    if result['decision']!='ALLOW': return JSONResponse(status_code=403,content={'aegis':result})
    return {'aegis':result,'resource':{'name':'Aegis demonstration item','released':True},'transaction':result.get('settlement',{})}

DEMO_REQUIREMENT=demo_requirement('http://demo.local/api/demo/resource')
@app.get('/api/demo/resource')
def demo_resource(request:Request):
    token=request.headers.get('PAYMENT-SIGNATURE') or request.headers.get('X-PAYMENT');resource='http://demo.local/api/demo/resource';req=dict(DEMO_REQUIREMENT,resource=resource)
    if not token:return JSONResponse(status_code=402,content={'x402Version':2,'error':'PAYMENT_REQUIRED','resource':{'url':resource,'description':'Aegis local protected resource','mimeType':'application/json'},'accepts':[req]})
    try:payment=json.loads(base64.b64decode(token).decode())
    except Exception:raise HTTPException(402,'invalid payment payload')
    p=x402_to_local(payment,req);r=local_requirements(req);ctx=RequestContext(method=request.method,path=request.url.path,resource=resource,merchant=req['payTo'],request_id=request.headers.get('X-Request-ID',str(uuid.uuid4())));result=gateway.inspect(p,r,ctx,time.time())
    if result['decision']!='ALLOW':return JSONResponse(status_code=402,content={'error':result['reason'],'aegis':result})
    return {'data':'protected resource released','aegis':{'decision':'ALLOW','fingerprint':result['fingerprint']},'settlement':result.get('settlement')}

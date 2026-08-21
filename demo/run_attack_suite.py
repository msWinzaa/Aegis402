import sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aegis402.gateway import AegisGateway
from aegis402.models import PaymentPayload,PaymentRequirements,RequestContext
from aegis402.x402_adapter import MockX402Adapter
def case(nonce='demo',resource='https://demo.local/api/resource',network='eip155:84532',signature='demo-signature'):
 r=PaymentRequirements(amount='1000',pay_to='merchant',resource=resource,network=network,asset='USDC');p=PaymentPayload(payer='wallet-demo',resource=resource,amount='1000',pay_to='merchant',nonce=nonce,network=network,asset='USDC',signature=signature);c=RequestContext(method='GET',path='/api/resource',resource=resource,merchant='merchant',request_id=nonce);return p,r,c
def main():
 out=[];p,r,c=case('normal');out.append(('normal',AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time())));p,r,c=case('cross');p.resource='https://demo.local/other';out.append(('cross-resource',AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time())));p,r,c=case('network');p.network='eip155:1';out.append(('network-substitution',AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time())));p,r,c=case('invalid');p.signature='invalid';out.append(('invalid-signature',AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time())));p,r,c=case('stale');out.append(('stale-requirements',AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time()-1000)));p,r,c=case('replay');g=AegisGateway(MockX402Adapter());out.extend([('replay-first',g.inspect(p,r,c,time.time())),('replay-second',g.inspect(p,r,c,time.time()))]);
 for n,d in out:print(f'{n:22} -> {d["decision"]:6} | {d["reason"]}')
if __name__=='__main__':main()

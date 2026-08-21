import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tempfile import TemporaryDirectory
from aegis402.identity import NodeIdentity
from aegis402.storage.sqlite import SQLiteStore
from aegis402.network.peer import PeerProtocol
from aegis402.network.reputation import ReputationNetwork
from aegis402.threats.reports import ThreatSigner,make_report,make_envelope
def main():
 with TemporaryDirectory() as d:
  root=Path(d);a=NodeIdentity('node-a',key_path=str(root/'a.pem'));b=NodeIdentity('node-b',key_path=str(root/'b.pem'));s=SQLiteStore(str(root/'b.db'));s.peer('node-a',{'endpoint':'http://node-a','public_identity':a.public_key,'trusted':True,'revoked':False,'trust':.8});p=PeerProtocol(s,b);r=make_report('node-a','replay','merchant',evidence_ref='ledger:event-1',confidence=.9,severity='high');ThreatSigner(a).sign(r);e=make_envelope('node-a',r);e.signature=a.sign(e.canonical());print('valid peer:',p.verify_envelope(e));print('replayed peer:',p.verify_envelope(e));e2=make_envelope('node-a',r);e2.signature=a.sign(e2.canonical());e2.report['target']='modified';print('modified peer:',p.verify_envelope(e2));rep=ReputationNetwork(s,'node-b');print('report ingest:',rep.ingest(r));print('reputation:',rep.score('merchant'))
if __name__=='__main__':main()

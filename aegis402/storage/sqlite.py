from __future__ import annotations
import json, sqlite3, threading, time
from pathlib import Path
class SQLiteStore:
    def __init__(self,path='aegis402.db'):
        self.path=Path(path); self._lock=threading.RLock(); self._init()
    def _conn(self):
        c=sqlite3.connect(self.path,check_same_thread=False,timeout=10,isolation_level=None); c.row_factory=sqlite3.Row; c.execute('PRAGMA busy_timeout=10000'); return c
    def _init(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._lock,self._conn() as c:c.executescript('''PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,value TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY,status TEXT NOT NULL,fingerprint TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS idempotency(key TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,decision TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,event_type TEXT NOT NULL,value TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS threats(report_id TEXT PRIMARY KEY,value TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS seen_messages(message_id TEXT PRIMARY KEY,sender_node TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS peers(node_id TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS reputation(target TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS reputation_observations(id INTEGER PRIMARY KEY AUTOINCREMENT,report_id TEXT NOT NULL,target TEXT NOT NULL,reporter_node TEXT NOT NULL,severity TEXT NOT NULL,confidence REAL NOT NULL,evidence_quality REAL NOT NULL,issuer_trust REAL NOT NULL,issued_at REAL NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS pending(fingerprint TEXT PRIMARY KEY,value TEXT NOT NULL,created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS peer_rate(peer_id TEXT PRIMARY KEY,window_start REAL NOT NULL,count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS revoked_identities(public_key TEXT PRIMARY KEY,node_id TEXT NOT NULL,revoked_at REAL NOT NULL);''')
    def set_config(self,k,v):
        with self._lock,self._conn() as c:c.execute('INSERT INTO config VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,json.dumps(v)))
    def get_config(self,k,default=None):
        with self._conn() as c:
            r=c.execute('SELECT value FROM config WHERE key=?',(k,)).fetchone(); return json.loads(r['value']) if r else default
    def list_config(self):
        with self._conn() as c:return {r['key']:json.loads(r['value']) for r in c.execute('SELECT key,value FROM config')}
    def put_policy(self,pid,value):
        now=time.time()
        with self._lock,self._conn() as c:c.execute('INSERT INTO policies(id,value,created_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',(pid,json.dumps(value),now,now))
    def delete_policy(self,pid):
        with self._lock,self._conn() as c:c.execute('DELETE FROM policies WHERE id=?',(pid,))
    def policies(self):
        with self._conn() as c:return [dict(id=r['id'],**json.loads(r['value'])) for r in c.execute('SELECT id,value FROM policies ORDER BY id')]
    def reserve_nonce(self,nonce,fingerprint):
        try:
            with self._lock,self._conn() as c:c.execute('INSERT INTO nonces VALUES(?,?,?,?)',(nonce,'reserved',fingerprint,time.time()))
            return True
        except sqlite3.IntegrityError:return False
    def consume_nonce(self,nonce):
        with self._lock,self._conn() as c:c.execute("UPDATE nonces SET status='consumed' WHERE nonce=?",(nonce,))
    def release_nonce(self,nonce):
        with self._lock,self._conn() as c:c.execute("DELETE FROM nonces WHERE nonce=? AND status='reserved'",(nonce,))
    def nonce_exists(self,nonce):
        with self._conn() as c:return c.execute('SELECT 1 FROM nonces WHERE nonce=?',(nonce,)).fetchone() is not None
    def put_idempotency(self,key,fingerprint,decision):
        try:
            with self._lock,self._conn() as c:c.execute('INSERT INTO idempotency VALUES(?,?,?,?)',(key,fingerprint,decision,time.time()))
            return True
        except sqlite3.IntegrityError:return False
    def get_idempotency(self,key):
        with self._conn() as c:
            r=c.execute('SELECT * FROM idempotency WHERE key=?',(key,)).fetchone(); return dict(r) if r else None
    def event(self,event_type,value):
        with self._lock,self._conn() as c:c.execute('INSERT INTO events(event_type,value,created_at) VALUES(?,?,?)',(event_type,json.dumps(value,sort_keys=True),time.time()))
    def spend_since(self,since):
        with self._conn() as c:return int(c.execute("SELECT COALESCE(SUM(CAST(json_extract(value,'$.amount') AS INTEGER)),0) total FROM events WHERE event_type='allowed_transaction' AND created_at>=?",(since,)).fetchone()['total'])
    def frequency_since(self,since):
        with self._conn() as c:return int(c.execute("SELECT COUNT(*) n FROM events WHERE event_type='allowed_transaction' AND created_at>=?",(since,)).fetchone()['n'])
    def events(self,limit=100):
        with self._conn() as c:return [dict(id=r['id'],event_type=r['event_type'],**json.loads(r['value']),created_at=r['created_at']) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,))]
    def threat(self,rid,value):
        with self._lock,self._conn() as c:c.execute('INSERT OR IGNORE INTO threats VALUES(?,?,?)',(rid,json.dumps(value,sort_keys=True),time.time()))
    def threat_exists(self,rid):
        with self._conn() as c:return c.execute('SELECT 1 FROM threats WHERE report_id=?',(rid,)).fetchone() is not None
    def threats(self):
        with self._conn() as c:return [json.loads(r['value']) for r in c.execute('SELECT value FROM threats ORDER BY created_at DESC')]
    def peer(self,node_id,value):
        with self._lock,self._conn() as c:c.execute('INSERT INTO peers VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',(node_id,json.dumps(value,sort_keys=True),time.time()))
    def peers(self):
        with self._conn() as c:return [dict(node_id=r['node_id'],**json.loads(r['value']),updated_at=r['updated_at']) for r in c.execute('SELECT * FROM peers')]
    def get_peer(self,node_id):
        with self._conn() as c:
            r=c.execute('SELECT node_id,value,updated_at FROM peers WHERE node_id=?',(node_id,)).fetchone(); return dict(node_id=r['node_id'],**json.loads(r['value']),updated_at=r['updated_at']) if r else None
    def reputation(self,target,value):
        with self._lock,self._conn() as c:c.execute('INSERT INTO reputation VALUES(?,?,?) ON CONFLICT(target) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',(target,json.dumps(value,sort_keys=True),time.time()))
    def reputations(self):
        with self._conn() as c:return [dict({'target':r['target'],'updated_at':r['updated_at']},**{k:v for k,v in json.loads(r['value']).items() if k!='updated_at'}) for r in c.execute('SELECT * FROM reputation')]
    def reputation_observation(self,**o):
        with self._lock,self._conn() as c:c.execute('INSERT INTO reputation_observations(report_id,target,reporter_node,severity,confidence,evidence_quality,issuer_trust,issued_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(o['report_id'],o['target'],o['reporter_node'],o['severity'],o['confidence'],o['evidence_quality'],o['issuer_trust'],o['issued_at'],time.time()))
    def observations(self,target):
        with self._conn() as c:return [dict(r) for r in c.execute('SELECT * FROM reputation_observations WHERE target=? ORDER BY issued_at DESC',(target,))]
    def seen_message(self,message_id,sender_node):
        try:
            with self._lock,self._conn() as c:c.execute('INSERT INTO seen_messages VALUES(?,?,?)',(message_id,sender_node,time.time()))
            return True
        except sqlite3.IntegrityError:return False
    def rate_limit(self,peer_id,limit,window=60):
        now=time.time()
        with self._lock,self._conn() as c:
            r=c.execute('SELECT window_start,count FROM peer_rate WHERE peer_id=?',(peer_id,)).fetchone()
            if not r or now-r['window_start']>=window:c.execute('INSERT INTO peer_rate VALUES(?,?,1) ON CONFLICT(peer_id) DO UPDATE SET window_start=excluded.window_start,count=1',(peer_id,now)); return True
            if r['count']>=limit:return False
            c.execute('UPDATE peer_rate SET count=count+1 WHERE peer_id=?',(peer_id,)); return True
    def revoke_identity(self,node_id,public_key):
        with self._lock,self._conn() as c:c.execute('INSERT OR REPLACE INTO revoked_identities VALUES(?,?,?)',(public_key,node_id,time.time()))
    def is_revoked_identity(self,public_key):
        with self._conn() as c:return c.execute('SELECT 1 FROM revoked_identities WHERE public_key=?',(public_key,)).fetchone() is not None
    def pending_put(self,fp,value):
        with self._lock,self._conn() as c:c.execute('INSERT OR REPLACE INTO pending VALUES(?,?,?)',(fp,json.dumps(value,sort_keys=True),time.time()))
    def pending_get(self,fp):
        with self._conn() as c:
            r=c.execute('SELECT value FROM pending WHERE fingerprint=?',(fp,)).fetchone(); return json.loads(r['value']) if r else None
    def pending_delete(self,fp):
        with self._lock,self._conn() as c:c.execute('DELETE FROM pending WHERE fingerprint=?',(fp,))
    def pending_all(self):
        with self._conn() as c:return [dict({'fingerprint':r['fingerprint']},**json.loads(r['value'])) for r in c.execute('SELECT fingerprint,value FROM pending ORDER BY created_at DESC')]

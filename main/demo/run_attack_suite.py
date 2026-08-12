import json
from fastapi.testclient import TestClient
from aegis402.app import app

client = TestClient(app)
scenarios = [
    'normal', 'cross-resource', 'replay', 'expired',
    'expired-authorization', 'wrong-network', 'invalid-signature',
    'cost', 'settlement-failure'
]
for attack in scenarios:
    data = client.post('/demo/check', json={'attack': attack}).json()
    first = data['first']
    second = data.get('second')
    print(f'{attack:24} -> {first["decision"]:5} | {first["reason"]}')
    if second:
        print(f'{"  replay attempt":24} -> {second["decision"]:5} | {second["reason"]}')
race = client.post('/demo/race').json()
print(f'{"20-way race":24} -> {race["allowed"]} ALLOW / {race["blocked"]} BLOCK')
print(json.dumps(client.get('/demo/ledger/verify').json(), indent=2))

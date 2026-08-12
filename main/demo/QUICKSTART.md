# main v0.1 — 3-minute judge demo

1. Install and run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn aegis402.app:app --reload
```

2. Open `http://127.0.0.1:8000/dashboard`.

3. Run **NORMAL PAYMENT**. Show `ALLOW` and the security checks.
4. Run **CROSS-RESOURCE**. Show `BLOCK` at context binding.
5. Run **REPLAY / NONCE**. Show the first attempt allowed and the replay blocked.
6. Run **SETTLEMENT FAILURE**. Show that verification alone does not produce an allow.
7. Run **20-WAY NONCE RACE**. Show exactly one request reaches the allow path.
8. Click **VERIFY LEDGER**. Show the hash chain is intact.

The demo is deliberately offline and uses `MockX402Adapter`. It demonstrates main's security logic without pretending that a mock payment is a real blockchain transaction.

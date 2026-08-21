# Aegis v1.0 demo

```bash
python demo/run_attack_suite.py
python demo/run_distributed_attack_suite.py
```

Run the application:

```bash
uvicorn aegis402.app:app --reload
```

Request `/api/demo/resource` without a payment to receive an x402 v2 `402 Payment Required` response. The local mock adapter accepts a deterministic demonstration payload. It is not blockchain settlement.

Configure the official x402 facilitator adapter for live verification/settlement as described in `docs/x402-integration.md`.

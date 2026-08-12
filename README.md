# Aegis402

Aegis402 is a local security middleware for x402 payment flows.

## Status

Version 0.1. Experimental prototype.

The default adapter is a deterministic local adapter intended for tests and attack simulation. The repository also contains an adapter boundary for integration with a live x402 facilitator.

## Scope

Aegis402 evaluates payment state before resource release. The prototype implements checks for:

- request and resource binding
- payment policy
- requirement freshness
- authorization validity windows
- nonce reservation and idempotency
- execution cost limits
- settlement response consistency
- hash-chained event records

The implementation does not replace x402 verification or blockchain settlement.

## Request path

The request enters the gateway before payment verification and resource release. The gateway evaluates the bound resource, merchant, amount, payment scheme, network and asset. It then evaluates freshness, authorization validity, execution limits and nonce state. Verification and settlement are delegated to the configured x402 adapter. A security event is written after the decision.

## Repository layout

`aegis402/` contains the security middleware.

`tests/` contains unit and attack-scenario tests.

`demo/` contains the local attack runner and demonstration material.

`dashboard/` contains the local HTTP interface.

`docs/` contains architecture, threat-model, attack-scenario and roadmap documents.

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn aegis402.app:app --reload
```

The dashboard is available at `http://127.0.0.1:8000/dashboard`.

The FastAPI interface is available at `http://127.0.0.1:8000/docs`.

## Tests

```bash
pytest -q
```

The attack tests include concurrent nonce reservation and ledger integrity checks.

## x402 adapter

`aegis402/x402_adapter.py` defines the adapter boundary used by the gateway.

`MockX402Adapter` is the default implementation. It does not perform live payment verification.

`X402FacilitatorAdapter` provides the integration boundary for the official x402 Python SDK and a facilitator endpoint. Live integration is not required for the local prototype.

## Security

See `SECURITY.md` for security assumptions, limitations and reporting information.

## Licence

MIT. See `LICENSE`.

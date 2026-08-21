# Aegis402 v1.0

Aegis is a local security agent for autonomous x402 payments. Each participating device runs its own Aegis node. The local deterministic gate remains authoritative even when peer intelligence is unavailable.

## Security boundary

Aegis does not custody consumer wallets. The consumer wallet signs the x402 authorization; Aegis receives payment evidence and evaluates it. Aegis node signing credentials are separate Ed25519 identity credentials.

The enforcement order is hard controls > local risk > peer intelligence/reputation > optional adaptive logic. Advisory components cannot convert a hard failure into `ALLOW`.

## Run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
source .venv/bin/activate
pip install -r requirements.txt
uvicorn aegis402.app:app --reload
```

Open `/dashboard` and `/docs`.

## x402

`AEGIS_X402_ADAPTER=mock` is a deterministic local simulator for tests. `AEGIS_X402_ADAPTER=facilitator` delegates x402 v2 verification and settlement to the official Python SDK/facilitator. Aegis never signs a consumer payment.

## Tests

```bash
python -m pytest -q
```

## Honest limitations

Aegis includes an experimental PBFT-style threat-intelligence consensus subsystem outside the payment path. Sybil resistance uses bounded influence, quarantine, diversity and admission controls; it is not perfect Sybil prevention. Keyed pseudonyms are not differential privacy/MPC/ZK. The local ledger is tamper-evident; batched Merkle roots can be externally anchored. Independent settlement verification is available through an EVM/RPC adapter when mechanism-specific chain evidence is configured.

## Production security posture

The production-hardening branch treats AI as probabilistic evidence and keeps deterministic controls authoritative. See `PRODUCTION_SECURITY_AND_COMPLIANCE.md` for the India/international compliance mapping and the remaining non-code assurance requirements.


## Runtime surfaces

- `/dashboard` consumer protection interface
- `/shop` live Base Sepolia x402 testnet transaction
- `/demo` local adversarial demonstration
- `/engineering` engineering/security observability
- `/explainer` visual system explainer
- `/admin` authenticated administrator control plane
- `/docs` FastAPI API reference

See `docs/live-demo.md` for the testnet demonstration configuration.

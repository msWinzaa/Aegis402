# Threat Model

## Assets

- payment authorization
- payment amount and destination
- resource authorization
- nonce and idempotency state
- settlement result
- local security records

## Attacker capabilities

The attacker may alter or replay payment data, substitute a resource or network, race concurrent requests, provide stale authorization data, provide an excessive execution-cost value, or cause inconsistent settlement responses.

The prototype does not model a compromised host, compromised private key, malicious operating system, or compromise of the underlying blockchain.

## Security boundaries

The main boundary is the main gateway between an incoming payment requirement and resource release.

External payment data crosses into the gateway. The gateway validates the data against locally maintained state and configured policy before calling the payment adapter.

## Security properties

main v0.1 aims to provide:

- resource and payment-context binding
- single-use nonce reservation
- freshness checks
- execution-cost limits
- settlement response consistency checks
- tamper detection for the local event chain

These properties are scoped to the prototype implementation. They are not claims about the complete x402 protocol or an underlying blockchain.

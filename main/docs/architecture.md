[architecture.md](https://github.com/user-attachments/files/30984056/architecture.md)[U# Architecture

## Components

Client

The component initiating the x402 request and payment.

main Gateway

The local enforcement point. It owns the security checks and controls whether the payment flow proceeds to the adapter.

x402 Adapter

The interface between main and payment verification and settlement. The prototype supplies a deterministic local adapter and a facilitator adapter.

Resource

The HTTP resource associated with the payment requirement.

Facilitator

External x402 verification and settlement service when the facilitator adapter is used.

Ledger

Local append-only event storage using hash chaining.

## Processing order

1. Parse the payment requirement.
2. Bind the payment to the expected resource and request context.
3. Apply payment policy.
4. Revalidate the payment requirement.
5. Validate the authorization time window when present.
6. Check execution limits.
7. Reserve the nonce and idempotency key.
8. Call the x402 adapter for verification and settlement.
9. Check the returned settlement data.
10. Record the decision in the ledger.
11. Release the resource only after an allowed result.

## Trust boundaries

The payment requirement, payment payload, client and facilitator response are treated as external input. Local policy, nonce state and the ledger are maintained by Aegis402.

The prototype does not assume that a valid payment response by itself establishes resource authorization.
ploading architecture.md…]()

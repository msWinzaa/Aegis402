# Attack Demonstration

The demonstration uses the local adapter. No live payment is required.

## Cases

`normal` is an ordinary payment request and should be allowed.

`cross-resource` changes the resource associated with an otherwise valid payment.

`replay` submits the same nonce more than once.

`expired` uses an old payment requirement.

`expired-authorization` uses an authorization outside its validity window.

`wrong-network` changes the expected network.

`invalid-signature` exercises the adapter validation path.

`cost` supplies an execution cost above the configured ceiling.

`settlement-failure` returns a failed settlement response.

`race` sends twenty concurrent requests using one nonce.

## Expected results

The normal case is allowed.

Cross-resource and network substitution are rejected by context binding.

The first use of a nonce is allowed and subsequent uses are rejected.

The concurrent race produces one allowed request and nineteen rejected requests.

Expired requirements and authorizations are rejected by the freshness checks.

A failed settlement does not release the resource.

Ledger verification reports whether the stored hash chain is intact.

## Local endpoints

`POST /demo/check` runs a selected case.

`POST /demo/race` runs the concurrent nonce test.

`GET /demo/ledger` returns the recorded events.

`GET /demo/ledger/verify` verifies the ledger chain.
[attacks.md](https://github.com/user-attachments/files/30983964/attacks.md)

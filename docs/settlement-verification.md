# Independent Settlement Verification

Aegis distinguishes facilitator settlement responses from independently observed blockchain state.

`SettlementAuthorisation` records the expected payer, recipient, amount, asset, network and payment fingerprint. `EVMSettlementVerifier` obtains the receipt through an RPC endpoint, checks transaction success, block inclusion, confirmation depth and network, and can consume a mechanism-specific event decoder for payer/recipient/amount/asset.

If receipt data cannot establish a field, the verifier does not invent it. The result is `unavailable` or a failed verification rather than an unconditional success.

An operator can configure confirmation depth. Reorganization-sensitive receipts below the threshold are held.

Exact event decoding remains mechanism-specific because x402 supports multiple payment schemes and assets.

# Aegis402 live demonstration

## Test network

The reference demonstration uses x402 v2 exact EVM on Base Sepolia (`eip155:84532`) with the USDC contract used by the x402 specification. The public x402 facilitator is suitable for this testnet flow; do not treat it as a production facilitator.

## Server

Set `AEGIS_X402_ADAPTER=facilitator`, `AEGIS_X402_NETWORK=eip155:84532`, `AEGIS_X402_ASSET=0x036CbD53842c5426634e7929541eC2318f3dCF7e`, `AEGIS_FACILITATOR_URL=https://x402.org/facilitator`, `AEGIS_RPC_URL=https://sepolia.base.org`, and `AEGIS_DEMO_PAY_TO` to the recipient wallet.

The server exposes `/shop`. An unpaid request returns HTTP 402 with a base64 `PAYMENT-REQUIRED` header. The browser wallet signs the EIP-712 `TransferWithAuthorization` payload. The signed x402 v2 payment is sent in `PAYMENT-SIGNATURE`. Aegis evaluates the request before calling the facilitator.

## Wallet

The demonstration never asks for a seed phrase or private key. The browser wallet signs locally. The payer must hold enough testnet USDC on Base Sepolia.

## Administrator

`/admin` is a separate surface. The password is supplied through `AEGIS_ADMIN_PASSWORD` in the hosting provider's secret environment, never in GitHub. The login endpoint issues a short-lived signed administrator session. The Git repository contains only `.env.example`.

## Production distinction

The live demonstration proves the testnet payment path. It does not prove production financial readiness. Mainnet requires a reviewed facilitator, production RPC, secret-management controls, operational monitoring, independent security review and the applicable compliance analysis.

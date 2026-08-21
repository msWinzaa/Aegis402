"""Settlement integrity.

Real guarantee vs. what a name like "Settlement Integrity" implies
---------------------------------------------------------------------
The x402 v2 core SettlementResponse (specs/transports-v2/http.md) only
guarantees: success, errorReason, transaction (tx hash), network, payer.
It does NOT guarantee a settled amount or a settled recipient -- some
facilitator deployments add extra fields (e.g. an "amount"), most don't,
and it is not part of the interoperable core contract. That means:

  - success / tx_hash / settled_network / payer below are checked against
    facts the adapter obtained from the facilitator's actual settlement
    response (when the adapter populates them) -- this is a real
    post-settlement guarantee.
  - the amount/pay_to checks below can only compare the CLIENT'S OWN
    payload against the requirements it was already checked against in
    binding.check_context_binding. They catch a caller whose payload
    changed between binding and settlement (or an adapter bug), but they
    are NOT an independent, on-chain confirmation that the settled amount
    equals the authorised amount. Getting that fact requires independently
    reading the settlement transaction (RPC / block explorer / a
    facilitator that opts into returning an amount), which is out of scope
    for v0.1 -- see docs/attack-scenarios.md, "Free Shopping" (Partial).

Callers should not read a PASS here as "the chain confirms the exact
amount moved"; they should read it as "settlement succeeded, is
self-consistent with what was authorised, and (where the adapter supplies
post-settlement facts) the network and payer match what actually settled".
"""


def verify_settlement_integrity(payload, requirements, result):
    if not result.success:
        return False, "settlement failed"
    if not result.tx_hash:
        return False, "successful settlement missing transaction hash"

    # Self-consistency only (payload vs requirements) -- see module
    # docstring for why this is not an independent on-chain check.
    if payload.amount != requirements.amount:
        return False, "claimed amount differs from authorised amount"
    if payload.pay_to != requirements.pay_to:
        return False, "claimed recipient differs from authorised recipient"

    # Real post-settlement facts, when the adapter supplies them.
    if result.settled_network is not None and result.settled_network != requirements.network:
        return False, "settlement network differs from authorised network"
    if result.payer is not None and result.payer != payload.payer:
        return False, "settlement payer differs from claimed payer"
    if result.settled_amount is not None and result.settled_amount != requirements.amount:
        return False, "settled amount (reported by facilitator) differs from authorised amount"

    return True, "settlement integrity passed"

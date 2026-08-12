from dataclasses import dataclass, field


@dataclass
class Policy:
    max_amount: int = 100_000
    allowed_paths: set[str] = field(default_factory=lambda: {"/api/resource"})
    allowed_merchants: set[str] = field(default_factory=set)
    # Empty set = no restriction (matches allowed_merchants' existing
    # "opt-in allowlist" convention: unset means "don't enforce this axis").
    allowed_networks: set[str] = field(default_factory=set)


def check_policy(payload, request, policy):
    try:
        amount = int(payload.amount)
    except ValueError:
        return False, "invalid amount"

    if amount < 0:
        return False, "negative amount"
    if amount > policy.max_amount:
        return False, "amount exceeds policy"
    if request.path not in policy.allowed_paths:
        return False, "endpoint not allowed"
    if policy.allowed_merchants and request.merchant not in policy.allowed_merchants:
        return False, "merchant not allowed"
    if policy.allowed_networks and payload.network not in policy.allowed_networks:
        return False, "network not allowed"

    return True, "policy passed"

"""Execution / cost guard.

Scope of the guarantee
-----------------------
`estimated_cost` is a number the CALLER supplies -- this module does not
measure anything itself (no gas simulation, no timing, no resource
metering). It is a policy ceiling on a self-reported figure, useful as a
circuit breaker once something upstream (the route handler, a gas
estimator, etc.) produces a real estimate, but it provides no guarantee on
its own against an attacker who simply reports a low `estimated_cost`
while causing expensive work. See docs/attack-scenarios.md, where "Service
Denial" and "Gas Abuse" are marked "Prototype" rather than "Yes" for this
reason.
"""

from dataclasses import dataclass


@dataclass
class ExecutionPolicy:
    max_cost_units: int = 100_000


def check_execution_cost(estimated_cost, policy):
    if estimated_cost < 0:
        return False, "negative execution cost"
    if estimated_cost > policy.max_cost_units:
        return False, "execution cost exceeds policy"
    return True, "execution cost passed"

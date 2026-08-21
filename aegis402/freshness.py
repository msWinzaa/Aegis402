"""Freshness / anti-staleness checks.

Two distinct things are checked here and they must not be conflated:

1. check_freshness -- is the *payment requirement* (the 402 challenge the
   merchant issued) still within its stated validity window? This guards
   against a stale, previously-issued requirement being replayed later
   (e.g. an old, lower price, or a requirement for a resource that has
   since been repriced/removed) -- a TOCTOU / stale-challenge attack. Its
   `issued_at` is server-side bookkeeping (when Aegis402/the merchant
   generated the requirement); it is NOT cryptographically bound to
   anything the payer signed, so it only protects against a stale
   *requirement*, not a stale or manipulated *payload*.

2. check_payload_validity_window -- is the payer's own signed authorization
   (when the scheme provides one, e.g. EIP-3009 validAfter/validBefore for
   the "exact" EVM scheme) currently within its window? Unlike issued_at,
   these two values are part of what the payer cryptographically committed
   to, so this check has a real security guarantee: it will not accept a
   payload whose own signed window has expired. When a payload does not
   carry a validity window (payload.valid_before is None) this check is a
   no-op PASS -- main has nothing to check locally, and the facilitator
   is the final authority on whether the underlying authorization is
   current.
"""

import time


def check_freshness(requirements, issued_at, now=None):
    now = time.time() if now is None else now
    age = now - issued_at

    if age < 0:
        return False, "challenge timestamp is in the future"
    if age > requirements.max_timeout_seconds:
        return False, "payment requirement expired"

    return True, "fresh"


def check_payload_validity_window(payload, now=None):
    now = time.time() if now is None else now

    valid_after = getattr(payload, "valid_after", None)
    valid_before = getattr(payload, "valid_before", None)

    if valid_after is None and valid_before is None:
        return True, "no signed validity window on payload"

    if valid_after is not None and now < valid_after:
        return False, "payload authorization not yet valid"
    if valid_before is not None and now > valid_before:
        return False, "payload authorization expired"

    return True, "payload authorization window valid"

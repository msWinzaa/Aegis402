# Threat Report Protocol

Version 1 reports contain report ID, reporter node, issued/expiry times, threat type, target, indicators, evidence reference, confidence, severity, context and signature.

The signed representation is canonical JSON with the signature field blank. Receivers validate schema, issuer trust, signature, freshness, expiry and report uniqueness. Unsigned reports are not authenticated intelligence.

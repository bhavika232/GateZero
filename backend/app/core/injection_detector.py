"""Prompt-injection detection on tool OUTPUT — NOT IMPLEMENTED YET (Phase 3, step 8).

Planned design:
- Configurable, explainable patterns (e.g. "ignore (all|previous) instructions",
  "you are now", "reveal your system prompt", requests to call other tools or send data out).
- detect(text) returns structured findings: {"rule": ..., "offset": ...} with no copied text.
- Policy setting `injection_policy`: "block" (default, approved) withholds the output and
  records outcome=output_blocked; "quarantine" returns it wrapped and labelled untrusted.

Known limits: heuristics have false positives (security articles quoting attacks) and false
negatives (paraphrased, encoded, or non-English injections). It reduces risk; it is not a guarantee.

Not wired into the gateway yet.
"""

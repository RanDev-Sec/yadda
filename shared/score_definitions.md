# Detection score definitions (DeTT&CT detection score)

Each score needs the evidence in the right-hand column. Record a score by hand with `yadda score`.

| Score | Meaning | Evidence |
|---|---|---|
| -1 | No detection | - |
| 0 | Data available for investigation/forensics only | Data source present, no rule |
| 1 | Rule deployed (set by `yadda run`) | Rule enabled in the environment's SecOps instance |
| 2 | Rule deployed, known limits | Rule fires, but narrow scope or FP rate above threshold (see comment) |
| 3 | Rule live and healthy | Has fired or been tested; FP rate under threshold |
| 4 | Validated in a test lab | Atomic Red Team test(s) passed; comment lists which tests (e.g. "4/9 atomics") |
| 5 | Validated in production | Test run in the production environment, with the owner's approval |

"Detected" in reports = latest score >= 3.

`yadda run` sets scores 1-3 itself. When it reads the deployed rules, a technique that a newly enabled rule covers gets
score 1, and a technique left with no rule drops to -1. Its evidence step then uses the rule health and
false-positive exports:
3 = a rule for the technique fired within the window (default 90 days) and is not noisy;
2 = it fires, but more than FP_MAX % of its closed cases were not malicious (needs at least MIN_CASES cases);
1 = never fired, not in the window, or not in the export.
It does not change a score of 4-5 or any score recorded with `yadda score`.

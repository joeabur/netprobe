# Findings and prioritization

The loopback-only `check-http` command can produce validation-required leads for selected missing HTTP security headers or cookie attributes. These are not proof of exploitability or confirmed misconfigurations. Only one HTTP `HEAD` response is observed; cookie values are intentionally discarded. Other checks do not currently produce findings. The `Finding` model supports severity, confidence, evidence, remediation, validation limitations, status, and references. CVSS is explicitly unset unless a future validated implementation supplies a genuine score.

`priority_score` is NetProbe prioritization, not CVSS: severity weight × confidence factor × exposure factor × evidence-quality factor, with an exposure/evidence baseline multiplier of 0.5 and rounding to an integer. Inputs are bounded 0–1. It must not be presented as a standardized vulnerability score. Findings can be marked open, accepted risk, false positive, or requiring validation.

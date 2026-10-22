# Contributing

Contributions must preserve the loopback-only scope boundary and must not add exploit, credential, stealth, or arbitrary-target functionality. Add tests for scope rejection and ensure no network I/O occurs before target authorization. Keep implementation claims aligned with verified behavior.

Run the checks listed in README.md before submitting. Use local fixtures only; tests must not contact public services.
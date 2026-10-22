# Configuration and scope

A scope file is mandatory for the supported CLI commands. Example:

    authorized_targets:
      - 127.0.0.1
      - "::1"
    exclusions: []
    authorization_confirmed: true

Only these scope keys are accepted. Targets may be loopback IPs/CIDRs or the literal `localhost`; hostnames are not resolved. Exclusions must be within an authorized loopback scope. All non-loopback/private/public targets and broad CIDRs are rejected. `examples/config.example.yaml` is illustrative; a general runtime settings loader is not implemented. CLI settings are bounded in code (64 ports, concurrency 16, timeout 5 seconds) and cannot disable loopback enforcement. `--artifact-dir` and `--output-dir` control local artifact locations; output names are validated and overwrite is opt-in.

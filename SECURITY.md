# Security policy

NetProbe v0.1.0 is restricted in code to loopback hosts. It provides bounded TCP connect checks, limited service observations, and selected HTTP checks; it is not a general-purpose network scanner. Do not use it to assess systems without explicit, written authorization. The scope acknowledgment is a user assertion, not an authorization mechanism.

Report suspected defects privately to the project maintainers with reproduction details that use only local fixtures. Do not include credentials, tokens, private keys, or third-party target data in reports. Assessment artifacts and reports default to restrictive mode 0600 file permissions and directories created with mode 0700 where supported. These are filesystem controls, not encryption. Store artifacts with access limited to the authorized assessment team and delete them according to the engagement retention policy. `netprobe-data/` is ignored by Git. HTTP cookie values and redirect `Location` values are not retained by the current observation parser.

Scope enforcement is intended to fail closed. Current network activity is limited to one explicitly authorized loopback host and selected ports. DNS assessment, broader host discovery, full TLS certificate validation, and automatic multi-host assessment orchestration are unsupported and must not be represented as implemented.

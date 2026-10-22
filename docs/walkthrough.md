# Local lab walkthrough

This exercise uses only a loopback-bound HTTP server on your own machine. NetProbe's technical scope is hard-coded to `localhost`, `127.0.0.0/8`, and `::1/128`; it rejects LAN and public addresses. All output examples below are illustrative, not captured program output. Assessment work requires permission even in a lab.

## 1. Install Python and NetProbe

Install Python 3.12 or later from a trusted distribution. From the repository root:

    python3.12 -m venv .venv
    . .venv/bin/activate
    python -m pip install --upgrade pip
    uv sync --extra dev

Without uv, use `python -m pip install -e '.[dev]'`. On Windows PowerShell, use `py -3.12 -m venv .venv`, then `.venv\Scripts\Activate.ps1`.

    netprobe version
    uv run pytest

Illustrative version output: `NetProbe 0.1.0`.

## 2. Start an isolated lab service

In terminal A, start Python's built-in HTTP server bound specifically to loopback:

    python -m http.server 8080 --bind 127.0.0.1

Keep it running. Do not change the bind address. In terminal B, activate the project environment from the repository root.

## 3. Validate scope

The example scope authorizes loopback only and requires `authorization_confirmed: true`. This records your acknowledgment; it does not expand the code-enforced scope or prove permission.

    netprobe validate-scope --scope examples/scope.example.yaml

Illustrative output contains `valid: true`, `127.0.0.1`, and `boundary: loopback-only`. Invalid or non-loopback targets return exit code 2 before network activity.

## 4. Dry-run and scan

Preview a single selected port. Dry-run validates the same scope, target, port-count, timeout, and concurrency limits as active scans, without connecting:

    netprobe scan --scope examples/scope.example.yaml --target 127.0.0.1 --ports 8080 --dry-run

Then, only for this authorized local fixture, make the TCP connect check:

    netprobe scan --scope examples/scope.example.yaml --target 127.0.0.1 --ports 8080 --i-have-authorization

Illustrative result: port 8080 is `open`. A connection refusal is `closed`; timeout or ambiguous socket errors are `unknown`. Explicit ports can include ranges; the limit is 64 unique ports.

## 5. Enumerate and check HTTP

Preview and then collect a bounded HTTP HEAD observation:

    netprobe enumerate --scope examples/scope.example.yaml --target 127.0.0.1 --port 8080 --protocol http --dry-run
    netprobe enumerate --scope examples/scope.example.yaml --target 127.0.0.1 --port 8080 --protocol http --i-have-authorization

Run selected security-header and cookie-attribute checks:

    netprobe check-http --scope examples/scope.example.yaml --target 127.0.0.1 --port 8080 --dry-run
    netprobe check-http --scope examples/scope.example.yaml --target 127.0.0.1 --port 8080 --i-have-authorization

The active check writes a private JSON assessment under `netprobe-data/assessments/` by default. Only one HEAD response is inspected. Cookie values and redirect `Location` values are not retained; only cookie-attribute presence flags are stored. Missing headers/attributes produce low-severity leads requiring validation, not confirmed vulnerabilities.

## 6. Run a one-host assessment and preview DNS

Orchestrate TCP checks and safe service inspections for selected ports on the same local host:

    netprobe assess --scope examples/scope.example.yaml --target 127.0.0.1 --ports 8080 --dry-run
    netprobe assess --scope examples/scope.example.yaml --target 127.0.0.1 --ports 8080 --i-have-authorization

The active command creates a private artifact containing port observations, service observations, applicable findings, scope metadata, and limitations. It only processes the selected single-host port set. TLS inspection on an explicitly selected HTTPS port reports leaf certificate dates and IP-SAN observations, but does not establish trust-chain validity or DNS hostname identity.

DNS is a single explicit query, not discovery. Preview a query for a local resolver you own and configured for the reserved `.test` name:

    netprobe dns-check --scope examples/scope.example.yaml --server 127.0.0.1 --name lab.test --type A --dry-run

An active query requires that DNS service on loopback plus the authorization acknowledgment. Names are limited to `localhost` and `.test`; only A, AAAA, MX, NS, and TXT are supported, with a three-second timeout cap. It does not contact a public resolver or perform zone transfers.

## 7. Generate JSON, CSV, and HTML reports

Use the latest assessment artifact:

    netprobe report --assessment latest --format json
    netprobe report --assessment latest --format csv
    netprobe report --assessment latest --format html

Reports are written to `netprobe-data/reports/`. The JSON retains structure, CSV includes assessment, observation, and finding rows, and HTML is escaped for untrusted values. Existing reports are not overwritten by default; add `--overwrite` only when replacement is intentional. Use `--assessment path/to/assessment.json` for a specific record and `--artifact-dir`/`--output-dir` to change locations.

Reports include executive summary, scope and exclusions, observations, severity distribution, technical findings, evidence, remediation, prioritization, and limitations. NetProbe priority is not CVSS.

## 8. Interpret and reproduce safely

Python's built-in server typically lacks modern browser security headers, so the check may create a `requires_validation` lead. That is an expected fixture observation, not proof that the server is exploitable. Reproduce only against this loopback service, verify the exact evidence, and do not generalize one HEAD response to other routes or production systems.

## 9. Fix and retest

The built-in server cannot be configured to add response security headers. To demonstrate remediation, replace it with a tiny local fixture application you own that sends a complete HEAD response with `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and appropriate test-cookie attributes. Bind it only to `127.0.0.1`; then rerun `check-http` and confirm those specific leads are absent in the observed response. Do not use real session cookies or credentials.

## 10. Troubleshooting and cleanup

- Scope error / exit 2: validate YAML, exact loopback address, and authorization acknowledgment.
- Active command asks for acknowledgment: add `--i-have-authorization` only for an authorized local lab.
- Connection refused: ensure the fixture is running on the exact selected port.
- Port already in use: stop the other local process or choose another loopback port and update command arguments.
- Report already exists: use a distinct `--name` or intentionally pass `--overwrite`.
- Environment mismatch: activate `.venv` and use `uv run` consistently.

Stop terminal A with Ctrl+C. Delete local data when no longer needed:

    rm -r netprobe-data

On Windows PowerShell use `Remove-Item -Recurse -Force netprobe-data`. Remove copied scope files and optionally `.venv`. Follow organizational retention rules and do not commit artifacts.

## Coverage limits

This release does not perform host discovery, DNS zone transfers, public DNS checks, trust-chain or DNS-hostname certificate validation, broad network assessment, CVE matching, or multi-host orchestration. DNS queries are explicit and limited to a scoped loopback resolver and reserved names. All scans/checks are bounded, single-host loopback operations; no claim of comprehensive penetration-testing coverage is made.

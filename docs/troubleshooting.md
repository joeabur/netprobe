# Troubleshooting

- `scope error`: confirm the YAML keys and indentation; targets must be loopback and authorization must be explicitly acknowledged.
- `Invalid or unsupported target`: use a literal IP, strict CIDR, or `localhost`; hostnames other than that literal are unsupported.
- `active assessment requires --target`: `assess` runs one explicitly scoped loopback host per invocation.
- `active ... requires --i-have-authorization`: acknowledge only when you have permission for the isolated lab activity.
- `DNS check input error`: resolver must be an explicitly scoped loopback IP; names are limited to `localhost` and reserved `.test` domains; one of A, AAAA, MX, NS, TXT must be selected. Active results are saved under `--artifact-dir`.
- `connection refused` or `incomplete` observations: confirm the local fixture is running on the requested port; timeouts are not treated as proof of closed/offline.
- `report already exists`: choose a new `--name` or intentionally pass `--overwrite`.
- `ModuleNotFoundError`: activate the project virtual environment and install with `python -m pip install -e '.[dev]'`.
- Tests and quality checks: run `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src/netprobe`, and `uv run bandit -r src/netprobe` from the repository root.

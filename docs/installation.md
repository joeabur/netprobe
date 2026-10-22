# Installation

NetProbe requires Python 3.12 or newer. Create and activate an isolated environment, then install the project and development extras:

    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install --upgrade pip
    uv sync --extra dev

Without uv, use `python -m pip install -e '.[dev]'`.

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. Validate with `netprobe version`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src/netprobe`, and `uv run bandit -r src/netprobe`. Active checks are restricted to explicitly scoped loopback hosts. See the [walkthrough](walkthrough.md) for the isolated local lab.

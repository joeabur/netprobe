"""Secure local JSON artifact storage with exclusive creation semantics."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ArtifactError(ValueError):
    """Raised for invalid artifact paths or invalid assessment data."""


def validate_artifact_name(name: str) -> str:
    if not _SAFE_NAME.fullmatch(name) or name in {".", ".."}:
        raise ArtifactError(
            "artifact name must contain only letters, digits, dot, underscore, hyphen"
        )
    return name


def write_json_artifact(directory: str | Path, name: str, document: dict[str, Any]) -> Path:
    """Write JSON using mode 0600 where supported; refuse to overwrite an existing file."""
    safe_name = validate_artifact_name(name)
    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = output_dir / f"{safe_name}.json"
    payload = json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ArtifactError(f"artifact already exists: {path}") from exc
    except OSError as exc:
        raise ArtifactError(f"cannot create artifact: {exc.strerror or exc}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ArtifactError(f"cannot write artifact: {exc.strerror or exc}") from exc
    return path


def load_json_artifact(path: str | Path) -> dict[str, Any]:
    artifact_path = Path(path)
    try:
        document = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read assessment artifact: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ArtifactError("unsupported or malformed assessment artifact")
    if not isinstance(document.get("metadata"), dict):
        raise ArtifactError("assessment artifact is missing metadata")
    if not isinstance(document.get("observations"), list) or not isinstance(
        document.get("findings"), list
    ):
        raise ArtifactError("assessment artifact requires observations and findings lists")
    return document


def latest_artifact(directory: str | Path) -> Path:
    """Return the newest regular JSON artifact in the directory."""
    output_dir = Path(directory)
    try:
        paths = [
            path for path in output_dir.glob("*.json") if path.is_file() and not path.is_symlink()
        ]
    except OSError as exc:
        raise ArtifactError(f"cannot list artifact directory: {exc}") from exc
    if not paths:
        raise ArtifactError(f"no assessment artifacts found in {output_dir}")
    return max(paths, key=lambda path: (path.stat().st_mtime_ns, path.name))

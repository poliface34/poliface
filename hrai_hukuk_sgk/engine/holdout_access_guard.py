"""WP-4.7 process-wide HOLDOUT file access guard (HOLDOUT_ACCESS_ALLOWED=false by default).

The guard is installed as a CPython audit hook (PEP 578) the first time the `engine` package is
imported, i.e. before any test, tool or engine code can touch a file. Audit hooks run inside the
interpreter for every `open` (builtins.open, io.open, os.open, pathlib, zipfile, shutil, ...), so the
decision is taken at the earliest access layer available to Python code, before the operating system
opens the file.

Protected paths come ONLY from vault registry metadata (`vaults[].file_relpath`); the protected files
themselves are never opened, read, hashed or parsed by this module.

Blocked while access is not allowed:
  - `open` of a protected path (any mode, any API that goes through the interpreter),
  - `os.remove` / `os.rename` / `os.truncate` / `os.link` / `os.symlink` / `shutil.copyfile` /
    `shutil.move` on a protected path,
  - `subprocess.Popen` whose argv/executable mentions a protected path or file name.

Access is allowed only when `HOLDOUT_ACCESS_ALLOWED` is exactly `true` AND no CI marker is set; in CI it
is unconditionally refused. Blocked attempts are counted (event name and API only, never content).
Metadata calls (`os.stat`, `os.path.exists`, directory listings) are not file reads and stay allowed.

Known limits (documented, not hidden): code running outside this interpreter (a separate process that
does not import `engine`), C extensions that bypass the interpreter's audit events, and hard links
created before the guard was installed are outside an in-process guard. `subprocess` launches that name
a protected file are refused for that reason.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any

HOLDOUT_ACCESS_ENV = "HOLDOUT_ACCESS_ALLOWED"
DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_RELPATH = "engine/evaluation/governance/holdout_vault_registry.json"
REGISTRY_SCHEMA = "hrai.holdout_vault_registry.v1"
CI_MARKERS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD", "CIRCLECI")

_PATH_EVENTS = {
    "open": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.truncate": (0,),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "shutil.copyfile": (0, 1),
    "shutil.move": (0, 1),
}


class HoldoutFileAccessBlocked(PermissionError):
    """Raised by the audit hook when a protected HOLDOUT path is accessed while access is not allowed."""


_lock = threading.Lock()
_state: dict[str, Any] = {
    "installed": False,
    "paths": set(),  # realpath strings
    "names": set(),  # file names (fast pre-filter)
    "roots": [],
    "blocked": [],  # (event, detail) - never content
}


def holdout_access_allowed(environment: Mapping[str, str] | None = None) -> bool:
    """True only for HOLDOUT_ACCESS_ALLOWED=true outside CI (custodian environment)."""
    env = os.environ if environment is None else environment
    if str(env.get(HOLDOUT_ACCESS_ENV, "")).strip() != "true":
        return False
    for key in CI_MARKERS:
        val = str(env.get(key, "") or "").strip().lower()
        if val and val not in {"0", "false", "no", "off"}:
            return False
    return True


def protected_holdout_paths(project_root: str | Path | None = None) -> tuple[Path, ...]:
    """Registered vault file paths under `project_root` (registry metadata only; fail-closed)."""
    root = Path(project_root).resolve() if project_root is not None else DEFAULT_PROJECT_ROOT
    reg = root / REGISTRY_RELPATH
    raw = json.loads(reg.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != REGISTRY_SCHEMA or not isinstance(raw.get("vaults"), list):
        raise RuntimeError(f"HOLDOUT registry schema must be {REGISTRY_SCHEMA}.")
    out: list[Path] = []
    for v in raw["vaults"]:
        rel = v.get("file_relpath") if isinstance(v, dict) else None
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise RuntimeError("HOLDOUT registry file_relpath must be a relative path inside the project.")
        out.append(Path(os.path.realpath(root / rel)))
    if not out:
        raise RuntimeError("HOLDOUT registry lists no vault file; refusing to run without a guard.")
    return tuple(sorted(out))


def _fspath(value: Any) -> str | None:
    if isinstance(value, int) or value is None:
        return None
    try:
        p = os.fspath(value)
    except TypeError:
        return None
    return os.fsdecode(p) if isinstance(p, bytes) else p


def _is_protected(path_str: str) -> bool:
    if os.path.basename(path_str) not in _state["names"]:
        return False
    try:
        return os.path.realpath(path_str) in _state["paths"]
    except (OSError, ValueError):
        return True  # cannot resolve a name that matches a protected file: fail closed


def _block(event: str, detail: str) -> None:
    _state["blocked"].append((event, detail))
    raise HoldoutFileAccessBlocked(
        f"HOLDOUT_ACCESS_ALLOWED=false: '{event}' on a registered HOLDOUT vault path was blocked before access."
    )


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if not _state["names"]:
        return
    idx = _PATH_EVENTS.get(event)
    if idx is not None:
        for i in idx:
            if i < len(args):
                ps = _fspath(args[i])
                if ps is not None and _is_protected(ps):
                    if holdout_access_allowed():
                        return
                    _block(event, os.path.basename(ps))
        return
    if event == "subprocess.Popen":
        executable, argv = (args + (None, None))[:2]
        parts: list[str] = []
        for item in ([executable] if executable is not None else []) + (
            list(argv) if isinstance(argv, (list, tuple)) else [argv]
        ):
            s = _fspath(item)
            if s is not None:
                parts.append(s)
        joined = "\0".join(parts)
        if any(name in joined for name in _state["names"]):
            if holdout_access_allowed():
                return
            _block(event, "argv mentions a protected HOLDOUT file")


def install_holdout_access_guard(project_root: str | Path | None = None) -> tuple[Path, ...]:
    """Install the audit hook once per process and register `project_root`'s vault paths (idempotent)."""
    paths = protected_holdout_paths(project_root)
    with _lock:
        _state["paths"].update(str(p) for p in paths)
        _state["names"].update(p.name for p in paths)
        root = str(Path(project_root).resolve() if project_root is not None else DEFAULT_PROJECT_ROOT)
        if root not in _state["roots"]:
            _state["roots"].append(root)
        if not _state["installed"]:
            sys.addaudithook(_audit_hook)
            _state["installed"] = True
    return paths


def guard_installed() -> bool:
    return bool(_state["installed"])


def guarded_paths() -> tuple[str, ...]:
    return tuple(sorted(_state["paths"]))


def blocked_attempts() -> tuple[tuple[str, str], ...]:
    """Blocked attempts so far in this process: (audit event, file name / reason). No content."""
    return tuple(_state["blocked"])

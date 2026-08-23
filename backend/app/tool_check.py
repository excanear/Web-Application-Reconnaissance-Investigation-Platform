"""Detects external CLI tools this project shells out to.

Distinguishes a genuinely missing binary from a same-named tool that
happens to be a different program. The concrete case that motivated
this module: the Python `httpx` HTTP-client package installs a CLI
script also named `httpx` on PATH (e.g. via pip), which silently
shadows ProjectDiscovery's `httpx` web-probing tool that
httpx_probe.py actually depends on -- same command name, unrelated
tool, and whichever one comes first on PATH wins. Resolving by name
alone is not enough; the resolved binary must be verified.
"""

import os
import shutil
import subprocess

WEBSCAN_HTTPX_PATH_ENV = "WEBSCAN_HTTPX_PATH"

# ProjectDiscovery's httpx uses single-dash Go-style flags (-version);
# the Python `httpx` package's CLI is click-based (double-dash, GNU
# style) and emits this exact banner when given a flag it doesn't
# recognize. That's a reliable signature to tell them apart instead of
# guessing at version-string formats, which could change per version.
_WRONG_HTTPX_MARKERS = ("Usage: httpx [OPTIONS] URL", "No such option")


class ToolResolutionError(RuntimeError):
    """Raised when an external tool this project depends on can't be
    resolved to a working, correctly-identified binary."""


def _candidates_on_path(name: str) -> list[str]:
    """Every executable named `name` found anywhere on PATH, not just
    the first. `shutil.which` only returns the first match, which is
    exactly what let a colliding same-named tool shadow the real one."""
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    exts = [""]
    if os.name == "nt":
        exts = os.environ.get("PATHEXT", ".EXE;.BAT;.CMD").split(os.pathsep)

    found: list[str] = []
    seen: set[str] = set()
    for directory in path_dirs:
        if not directory:
            continue
        for ext in exts:
            candidate = os.path.join(directory, name + ext)
            key = candidate.lower()
            if key in seen:
                continue
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                seen.add(key)
                found.append(candidate)
    return found


def _is_projectdiscovery_httpx(path: str) -> bool:
    try:
        result = subprocess.run(
            [path, "-version"], capture_output=True, text=True, timeout=10
        )
    except OSError:
        return False
    combined = (result.stdout or "") + (result.stderr or "")
    return not any(marker in combined for marker in _WRONG_HTTPX_MARKERS)


def resolve_httpx_binary() -> str:
    """Return the path to a working ProjectDiscovery httpx binary.

    Checked in this order: an explicit WEBSCAN_HTTPX_PATH override,
    then every `httpx` found anywhere on PATH (not just the first,
    since the wrong one commonly comes first), each verified by
    actually running it and checking for the colliding tool's
    signature banner."""
    override = os.environ.get(WEBSCAN_HTTPX_PATH_ENV)
    if override:
        if _is_projectdiscovery_httpx(override):
            return override
        raise ToolResolutionError(
            f"{WEBSCAN_HTTPX_PATH_ENV}={override} does not look like "
            "ProjectDiscovery's httpx (it responded like the unrelated "
            "Python `httpx` package's CLI)."
        )

    candidates = _candidates_on_path("httpx")
    for candidate in candidates:
        if _is_projectdiscovery_httpx(candidate):
            return candidate

    if candidates:
        raise ToolResolutionError(
            "Found 'httpx' on PATH, but it's the Python HTTP-client "
            "package's CLI, not ProjectDiscovery's httpx probing tool "
            "(same command name, different tool). Install the real one "
            "with `go install "
            "github.com/projectdiscovery/httpx/cmd/httpx@latest` and make "
            "sure its install dir (usually $(go env GOPATH)/bin) comes "
            f"before the Python Scripts dir on PATH, or set "
            f"{WEBSCAN_HTTPX_PATH_ENV} to its full path."
        )
    raise ToolResolutionError(
        "httpx (ProjectDiscovery) not found on PATH. Install with `go "
        "install github.com/projectdiscovery/httpx/cmd/httpx@latest`."
    )


def check_generic_tool(name: str, version_args: list[str] | None) -> dict:
    """Presence check for tools with no known same-name collision --
    just confirm the binary exists (and, if version_args is given,
    that it actually runs) rather than deep-verifying its identity."""
    path = shutil.which(name)
    if path is None:
        return {"name": name, "found": False, "path": None}

    result: dict = {"name": name, "found": True, "path": path}
    if version_args is not None:
        try:
            subprocess.run(
                [path, *version_args], capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["warning"] = str(exc)
    return result


# (name, version_args). msfconsole is presence-only (None): actually
# invoking it spins up the full Ruby framework, far too slow for a
# preflight check.
_GENERIC_TOOLS: list[tuple[str, list[str] | None]] = [
    ("nuclei", ["-version"]),
    ("subfinder", ["-version"]),
    ("nmap", ["--version"]),
    ("msfconsole", None),
    ("testssl.sh", None),
]


def preflight_report() -> list[dict]:
    """One status dict per external tool this project's active modules
    depend on, each with `ok` set for whether the scan can actually use
    it. Meant to be surfaced up front (persisted findings, `webscan
    doctor`) instead of only showing up buried in a module_error/audit
    entry after the fact."""
    report: list[dict] = []

    try:
        path = resolve_httpx_binary()
        report.append({"name": "httpx", "found": True, "ok": True, "path": path})
    except ToolResolutionError as exc:
        report.append(
            {"name": "httpx", "found": False, "ok": False, "detail": str(exc)}
        )

    for name, version_args in _GENERIC_TOOLS:
        result = check_generic_tool(name, version_args)
        result["ok"] = result["found"]
        if not result["found"]:
            result["detail"] = f"{name} not found on PATH"
        report.append(result)

    return report

import os
import stat

import pytest

from app.tool_check import (
    ToolResolutionError,
    _candidates_on_path,
    _is_projectdiscovery_httpx,
    check_generic_tool,
    resolve_httpx_binary,
)


def _write_fake_binary(tmp_path, name, script_body):
    """Write a fake executable script that a subprocess.run(["<path>", ...])
    call can actually invoke, so tests exercise real process behavior
    instead of mocking subprocess.run (which would just prove the mock
    works, not that the detection logic correctly distinguishes tools)."""
    if os.name == "nt":
        path = tmp_path / f"{name}.bat"
        path.write_text("@echo off\r\n" + script_body + "\r\n")
    else:
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + script_body + "\n")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_is_projectdiscovery_httpx_true_for_a_real_looking_go_style_binary(tmp_path):
    path = _write_fake_binary(tmp_path, "realhttpx", 'echo "httpx version v1.6.5"')
    assert _is_projectdiscovery_httpx(path) is True


def test_is_projectdiscovery_httpx_false_for_click_style_wrong_tool(tmp_path):
    # Mirrors the real collision: the Python `httpx` package's click-based
    # CLI rejects a single-dash flag with this exact banner.
    path = _write_fake_binary(
        tmp_path,
        "wronghttpx",
        'echo "Usage: httpx [OPTIONS] URL" 1>&2 && echo "Error: No such option \'-v\'." 1>&2',
    )
    assert _is_projectdiscovery_httpx(path) is False


def test_candidates_on_path_finds_every_match_not_just_the_first(tmp_path, monkeypatch):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    path_a = _write_fake_binary(dir_a, "mytool", "echo a")
    path_b = _write_fake_binary(dir_b, "mytool", "echo b")
    monkeypatch.setenv("PATH", os.pathsep.join([str(dir_a), str(dir_b)]))

    found = [p.lower() for p in _candidates_on_path("mytool")]

    assert path_a.lower() in found
    assert path_b.lower() in found


def test_resolve_httpx_binary_skips_wrong_tool_and_returns_the_real_one(tmp_path, monkeypatch):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    # Wrong tool shadows the real one by coming first on PATH -- this is
    # exactly the failure mode that broke httpx_probe on Windows.
    wrong = _write_fake_binary(
        dir_a,
        "httpx",
        'echo "Usage: httpx [OPTIONS] URL" 1>&2 && echo "Error: No such option." 1>&2',
    )
    real = _write_fake_binary(dir_b, "httpx", 'echo "httpx version v1.6.5"')
    monkeypatch.setenv("PATH", os.pathsep.join([str(dir_a), str(dir_b)]))
    monkeypatch.delenv("WEBSCAN_HTTPX_PATH", raising=False)

    resolved = resolve_httpx_binary()

    assert resolved.lower() == real.lower()
    assert resolved.lower() != wrong.lower()


def test_resolve_httpx_binary_raises_actionable_error_when_only_wrong_tool_found(
    tmp_path, monkeypatch
):
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    _write_fake_binary(
        dir_a,
        "httpx",
        'echo "Usage: httpx [OPTIONS] URL" 1>&2 && echo "Error: No such option." 1>&2',
    )
    monkeypatch.setenv("PATH", str(dir_a))
    monkeypatch.delenv("WEBSCAN_HTTPX_PATH", raising=False)

    with pytest.raises(ToolResolutionError, match="Python HTTP-client package"):
        resolve_httpx_binary()


def test_resolve_httpx_binary_raises_when_nothing_found_on_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("WEBSCAN_HTTPX_PATH", raising=False)

    with pytest.raises(ToolResolutionError, match="not found on PATH"):
        resolve_httpx_binary()


def test_resolve_httpx_binary_honors_explicit_override(tmp_path, monkeypatch):
    real = _write_fake_binary(tmp_path, "customhttpx", 'echo "httpx version v1.6.5"')
    monkeypatch.setenv("WEBSCAN_HTTPX_PATH", real)

    assert resolve_httpx_binary() == real


def test_resolve_httpx_binary_rejects_a_wrong_explicit_override(tmp_path, monkeypatch):
    wrong = _write_fake_binary(
        tmp_path,
        "customhttpx",
        'echo "Usage: httpx [OPTIONS] URL" 1>&2 && echo "Error: No such option." 1>&2',
    )
    monkeypatch.setenv("WEBSCAN_HTTPX_PATH", wrong)

    with pytest.raises(ToolResolutionError, match="WEBSCAN_HTTPX_PATH"):
        resolve_httpx_binary()


def test_check_generic_tool_reports_missing_when_not_on_path(monkeypatch):
    monkeypatch.setattr("app.tool_check.shutil.which", lambda name: None)

    result = check_generic_tool("nmap", ["--version"])

    assert result == {"name": "nmap", "found": False, "path": None}


def test_check_generic_tool_reports_found_when_on_path(tmp_path, monkeypatch):
    path = _write_fake_binary(tmp_path, "nmap", 'echo "Nmap version 7.98"')
    monkeypatch.setattr("app.tool_check.shutil.which", lambda name: path)

    result = check_generic_tool("nmap", ["--version"])

    assert result["found"] is True
    assert result["path"] == path

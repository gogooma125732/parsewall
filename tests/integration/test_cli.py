import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from injection_firewall import cli

SOURCE_ROOT = Path(__file__).parents[2] / "src"


def run_cli(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {"PYTHONPATH": str(SOURCE_ROOT)}
    return subprocess.run(
        [sys.executable, "-m", "injection_firewall.cli", *arguments],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


def test_cli_prints_only_compact_public_result_and_writes_requested_result(tmp_path: Path):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    result_path = tmp_path / "published" / "scan.json"

    completed = run_cli(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(result_path),
        ]
    )

    expected = '{"risk_level":"low","evidence":[],"location":[],"structural_anomalies":[]}\n'
    assert completed.returncode == 0
    assert completed.stdout == expected
    assert completed.stderr == ""
    assert result_path.read_text("utf-8") == expected


def test_cli_never_echoes_source_text_or_path_in_operational_error(tmp_path: Path):
    secret = "EXFILTRATE_this_document"
    source = tmp_path / f"{secret}.pdf"
    source.write_bytes(b"%PDF-1.7\n")

    completed = run_cli(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(tmp_path / "scan.json"),
        ]
    )

    result = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert set(result) == {"risk_level", "evidence", "location", "structural_anomalies"}
    assert secret not in completed.stdout
    assert secret not in completed.stderr


def test_cli_unknown_argument_is_fixed_source_free_error(tmp_path: Path):
    secret = "/secret/source/path"

    completed = run_cli(["scan", secret])

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "scan arguments invalid\n"


def test_cli_result_alias_to_derivative_is_rejected_without_overwrite(tmp_path: Path):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    output_dir = tmp_path / "out"

    completed = run_cli(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(output_dir),
            "--result",
            str(output_dir / "visible.txt"),
        ]
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "scan output failed\n"
    assert not (output_dir / "visible.txt").exists()


def test_cli_rejects_unowned_private_requested_target_before_scan(tmp_path: Path):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    output_dir = tmp_path / "out"
    result_path = tmp_path / "published" / "scan.json"
    result_path.parent.mkdir()
    result_path.write_bytes(b"unowned requested result")
    result_path.chmod(0o600)

    completed = run_cli(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(output_dir),
            "--result",
            str(result_path),
        ]
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "scan output failed\n"
    assert result_path.read_bytes() == b"unowned requested result"
    assert not output_dir.exists()


def test_cli_rejects_hardlink_requested_source_alias_without_change(tmp_path: Path):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    source.chmod(0o600)
    result_path = tmp_path / "scan.json"
    os.link(source, result_path)

    completed = run_cli(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(result_path),
        ]
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "scan output failed\n"
    assert source.read_text("utf-8") == "ordinary report"
    assert result_path.read_text("utf-8") == "ordinary report"
    assert not (tmp_path / "out").exists()


class _CaptureBuffer:
    def __init__(self) -> None:
        self.contents = bytearray()

    def write(self, payload: bytes) -> int:
        self.contents.extend(payload)
        return len(payload)

    def flush(self) -> None:
        return None


class _Stdout:
    def __init__(self) -> None:
        self.buffer = _CaptureBuffer()


class _Stderr:
    def __init__(self) -> None:
        self.contents = ""

    def write(self, payload: str) -> int:
        self.contents += payload
        return len(payload)


def test_cli_requested_parent_swap_after_path_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    requested_root = tmp_path / "requested"
    pivot = requested_root / "pivot"
    outside = tmp_path / "outside"
    pivot.mkdir(parents=True)
    outside.mkdir()
    real_is_symlink = Path.is_symlink
    swapped = False

    def swap_after_check(path: Path) -> bool:
        nonlocal swapped
        answer = real_is_symlink(path)
        if path == pivot and not swapped:
            swapped = True
            path.rmdir()
            path.symlink_to(outside, target_is_directory=True)
        return answer

    stdout = _Stdout()
    stderr = _Stderr()
    monkeypatch.setattr(Path, "is_symlink", swap_after_check)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    returncode = cli.main(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(pivot / "scan.json"),
        ]
    )

    assert returncode == 0
    assert stderr.contents == ""
    assert json.loads(stdout.buffer.contents) == {
        "risk_level": "low",
        "evidence": [],
        "location": [],
        "structural_anomalies": [],
    }
    assert not (outside / "scan.json").exists()


def test_cli_requested_parent_renamed_after_open_cannot_spoof_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    root = tmp_path / "requested"
    pivot = root / "pivot"
    moved = root / "moved"
    pivot.mkdir(parents=True)
    real_open = os.open
    pivot_opens = 0

    def swap_on_requested_open(path, flags, *args, dir_fd=None, **kwargs):
        nonlocal pivot_opens
        descriptor = real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)
        if path == "pivot":
            pivot_opens += 1
            if pivot_opens == 2:
                pivot.rename(moved)
                pivot.mkdir()
                (pivot / "scan.json").write_bytes(b'{"attacker":true}\n')
        return descriptor

    stdout = _Stdout()
    stderr = _Stderr()
    monkeypatch.setattr("injection_firewall.derivative.os.open", swap_on_requested_open)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    returncode = cli.main(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(pivot / "scan.json"),
        ]
    )

    assert returncode == 1
    assert stdout.buffer.contents == b""
    assert stderr.contents == "scan output failed\n"
    assert (pivot / "scan.json").read_bytes() == b'{"attacker":true}\n'
    assert not (moved / "scan.json").exists()
    assert not (tmp_path / "out").exists()


def test_cli_requested_parent_detached_after_commit_still_revokes_genuine_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    requested_root = tmp_path / "requested"
    requested_root.mkdir()
    moved = tmp_path / "moved"
    requested = requested_root / "scan.json"
    real_write_result = cli.write_result

    def detach_after_commit(path, result):
        installed = real_write_result(path, result)
        requested_root.rename(moved)
        requested_root.mkdir()
        requested.write_bytes(b'{"attacker":true}\n')
        return installed

    stdout = _Stdout()
    stderr = _Stderr()
    monkeypatch.setattr(cli, "write_result", detach_after_commit)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    returncode = cli.main(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--result",
            str(requested),
        ]
    )

    assert returncode == 1
    assert stdout.buffer.contents == b""
    assert stderr.contents == "scan output failed\n"
    assert requested.read_bytes() == b'{"attacker":true}\n'
    assert not (moved / "scan.json").exists()
    assert not (tmp_path / "out").exists()


def test_cli_output_parent_detached_after_scan_still_revokes_genuine_low(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    output_root = tmp_path / "output-root"
    output_root.mkdir()
    moved = tmp_path / "moved-output"
    output_dir = output_root / "out"
    real_scan_file = cli.scan_file

    def detach_after_scan(path, output, limits):
        artifacts = real_scan_file(path, output, limits)
        output_root.rename(moved)
        output_root.mkdir()
        output_dir.mkdir()
        (output_dir / "result.json").write_bytes(b'{"attacker":true}\n')
        (output_dir / "visible.txt").write_bytes(b"ATTACKER")
        return artifacts

    stdout = _Stdout()
    stderr = _Stderr()
    monkeypatch.setattr(cli, "scan_file", detach_after_scan)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    returncode = cli.main(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(output_dir),
            "--result",
            str(tmp_path / "scan.json"),
        ]
    )

    assert returncode == 1
    assert stdout.buffer.contents == b""
    assert stderr.contents == "scan output failed\n"
    assert (output_dir / "visible.txt").read_bytes() == b"ATTACKER"
    assert not (moved / "out").exists()


def test_cli_failure_before_requested_install_revokes_internal_low_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "safe.txt"
    source.write_text("ordinary report", encoding="utf-8")
    output_dir = tmp_path / "out"
    result_path = tmp_path / "published" / "scan.json"
    stdout = _Stdout()
    stderr = _Stderr()

    def fail_requested_result(*args, **kwargs):
        raise OSError("failure before requested install")

    monkeypatch.setattr(cli, "write_result", fail_requested_result)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    returncode = cli.main(
        [
            "scan",
            "--input",
            str(source),
            "--output-dir",
            str(output_dir),
            "--result",
            str(result_path),
        ]
    )

    assert returncode == 1
    assert stdout.buffer.contents == b""
    assert stderr.contents == "scan output failed\n"
    assert not result_path.exists()
    assert not output_dir.exists()

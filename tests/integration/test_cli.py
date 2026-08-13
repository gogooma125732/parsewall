import json
import os
import subprocess
import sys
from pathlib import Path

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

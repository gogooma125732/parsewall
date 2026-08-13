"""Fixed renderer/OCR execution with no shell, network, or inherited secrets."""

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .limits import ScanLimits


@dataclass(frozen=True, slots=True)
class ExecutablePolicy:
    tesseract: Path
    libreoffice: Path | None = None
    ocr_language: str = "eng"


def _validated_executable(path: Path) -> str:
    if not path.is_absolute():
        raise ValueError("executable must be absolute")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise ValueError("executable unavailable")
    return os.fspath(path)


def _environment(work_dir: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(work_dir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": os.fspath(work_dir),
    }


def run_fixed(
    executable: Path,
    arguments: tuple[str, ...],
    work_dir: Path,
    limits: ScanLimits,
    *,
    max_output_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    completed = subprocess.run(
        [_validated_executable(executable), *arguments],
        cwd=work_dir,
        env=_environment(work_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        shell=False,
        timeout=limits.max_seconds,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > max_output_bytes:
        raise RuntimeError("fixed executable failed")
    return completed.stdout


def ocr_image(
    image_path: Path,
    policy: ExecutablePolicy,
    limits: ScanLimits,
) -> str:
    output = run_fixed(
        policy.tesseract,
        (os.fspath(image_path), "stdout", "-l", policy.ocr_language),
        image_path.parent,
        limits,
    )
    return output.decode("utf-8", "strict")


def render_presentation(
    source_path: Path,
    output_dir: Path,
    policy: ExecutablePolicy,
    limits: ScanLimits,
) -> Path:
    if policy.libreoffice is None:
        raise FileNotFoundError("renderer unavailable")
    run_fixed(
        policy.libreoffice,
        ("--headless", "--convert-to", "pdf", "--outdir", os.fspath(output_dir), os.fspath(source_path)),
        output_dir,
        limits,
    )
    rendered = output_dir / f"{source_path.stem}.pdf"
    if not rendered.is_file() or rendered.stat().st_size > limits.max_upload_bytes * 4:
        raise RuntimeError("renderer output invalid")
    return rendered

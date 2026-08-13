"""One-shot isolated worker over trusted opaque job identifiers."""

import argparse
import os
import time
from pathlib import Path

from .contract import ScanResult
from .engine import scan_file
from .executables import ExecutablePolicy
from .job_store import JobStore
from .policy import FailureKind, failure_finding


def executable_policy_from_environment() -> ExecutablePolicy | None:
    tesseract = os.environ.get("DIF_TESSERACT")
    if not tesseract:
        return None
    libreoffice = os.environ.get("DIF_LIBREOFFICE")
    return ExecutablePolicy(
        Path(tesseract),
        Path(libreoffice) if libreoffice else None,
        os.environ.get("DIF_OCR_LANGUAGE", "eng"),
    )


def process_job(store: JobStore, job_id: str) -> bool:
    source = store.claim(job_id)
    if source is None:
        return False
    try:
        artifacts = scan_file(source, store.limits, executable_policy_from_environment())
        store.publish(job_id, artifacts.result, artifacts.derivative_text)
    except Exception:  # noqa: BLE001 -- worker boundary publishes an opaque quarantine.
        failure = ScanResult.from_findings((failure_finding(FailureKind.UNKNOWN),))
        store.publish(job_id, failure, None)
    return True


def run_pending(store: JobStore, *, maximum: int | None = None) -> int:
    processed = 0
    for job_id in store.pending_ids():
        if maximum is not None and processed >= maximum:
            break
        processed += int(process_job(store, job_id))
    return processed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="document-firewall-worker")
    parser.add_argument("--store", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=0.5)
    arguments = parser.parse_args(argv)
    store = JobStore(Path(arguments.store))
    if arguments.once:
        run_pending(store, maximum=1)
        return 0
    if arguments.interval <= 0:
        parser.error("interval must be positive")
    while True:
        run_pending(store)
        time.sleep(arguments.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

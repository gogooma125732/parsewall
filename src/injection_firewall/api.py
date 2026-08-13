"""Independent HTTP upload/status/result API; scanning remains in the worker."""

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.datastructures import UploadFile

from .job_store import JobStatus, JobStore


def create_app(store_root: Path | None = None) -> FastAPI:
    root = store_root or Path(os.environ.get("DIF_JOB_STORE", "/var/lib/dif/jobs"))
    store = JobStore(root)
    app = FastAPI(title="Document Injection Firewall", version="1.0.0")
    app.state.store = store

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/scans", status_code=202)
    async def upload(request: Request) -> dict[str, str]:
        try:
            async with request.form(
                max_files=1,
                max_fields=0,
                max_part_size=store.limits.max_upload_bytes,
            ) as form:
                file = form.get("file")
                if not isinstance(file, UploadFile):
                    raise TypeError("one file is required")
                file.file.seek(0)
                record = store.create(file.filename or "upload.unsupported", file.file)
        except MemoryError as error:
            raise HTTPException(status_code=413, detail="upload rejected") from error
        except Exception as error:
            raise HTTPException(status_code=400, detail="upload rejected") from error
        return {"job_id": record.job_id, "status": record.status.value}

    @app.get("/v1/scans/{job_id}")
    def status(job_id: str) -> dict[str, str]:
        try:
            record = store.record(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="unknown job") from error
        return {"job_id": record.job_id, "status": record.status.value}

    @app.get("/v1/scans/{job_id}/result")
    def result(job_id: str) -> JSONResponse:
        try:
            record = store.record(job_id)
            if record.status is not JobStatus.COMPLETE:
                raise HTTPException(status_code=409, detail="result unavailable")
            scan_result = store.result(job_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="unknown job") from error
        return JSONResponse(scan_result.to_public_dict())

    @app.get("/v1/scans/{job_id}/derivative")
    def derivative(job_id: str) -> PlainTextResponse:
        try:
            return PlainTextResponse(store.derivative(job_id), media_type="text/plain; charset=utf-8")
        except (KeyError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail="derivative unavailable") from error

    return app


def main() -> None:
    uvicorn.run(
        "injection_firewall.api:create_app",
        factory=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )

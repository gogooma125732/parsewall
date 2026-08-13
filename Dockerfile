FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DIF_TESSERACT=/usr/bin/tesseract \
    DIF_LIBREOFFICE=/usr/bin/libreoffice

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
        libreoffice-impress \
        tesseract-ocr \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 firewall \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent firewall

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN install -d -o firewall -g firewall -m 0700 /var/lib/dif/jobs
USER 65532:65532

ENTRYPOINT ["document-firewall-api"]

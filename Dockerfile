# XSSentinel — single-container image (core engine, no headless browser).
#
# The L6 real-browser DOM confirmation needs Playwright + Chromium (~300 MB);
# keep it out of the base image and layer it on top when needed:
#   FROM ghcr.io/feixingxuerong123/xssentinel:latest
#   RUN pip install playwright && playwright install chromium --with-deps
# Without it the DOM engine degrades to static heuristics (documented behavior).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# README.md is part of the wheel metadata (pyproject readme = "README.md").
COPY pyproject.toml README.md ./
COPY xssentinel ./xssentinel

RUN pip install --no-cache-dir .

# Non-root by default; reports are written to the mounted working directory.
RUN useradd --create-home --shell /usr/sbin/nologin scanner
USER scanner

WORKDIR /scans
ENTRYPOINT ["xssentinel"]
CMD ["--help"]

# The dashboard image (plan 9.2). It holds code, settings and the embedding model; no data, no key.
FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    HF_HOME=/opt/huggingface
WORKDIR /app

COPY pyproject.toml uv.lock .python-version ./
# XGBoost asks for NCCL on Linux, 471 MB that only multi-GPU training uses.
RUN uv sync --frozen --no-dev --no-install-project --no-install-package nvidia-nccl-cu12

# Baked at build time, so `docker compose up` needs no network for it (D52).
# tests/test_docker.py keeps these two equal to `rag` in configs/default.yaml.
ARG EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
ARG EMBEDDING_REVISION=5c38ec7c405ec4b44b94cc5a9bb96e735b38267a
RUN .venv/bin/python -c "import os; from huggingface_hub import snapshot_download; \
snapshot_download(os.environ['EMBEDDING_MODEL'], revision=os.environ['EMBEDDING_REVISION'], \
ignore_patterns=['onnx/*', 'openvino/*', 'pytorch_model.bin'])"

COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --no-install-package nvidia-nccl-cu12


FROM python:3.11-slim

# `investigate` refuses the test testbed where this file exists (D53).
RUN touch /etc/logtriage-container \
    && useradd --uid 1000 --create-home app

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/huggingface \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    LOGTRIAGE_APP__HOST=0.0.0.0
WORKDIR /app

COPY --from=builder /opt/huggingface /opt/huggingface
COPY --from=builder /app/.venv /app/.venv
COPY configs ./configs
COPY data_meta ./data_meta

USER app
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD ["python", "-c", "import urllib.request as r; r.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"]
CMD ["logtriage", "app", "--testbed", "santos"]

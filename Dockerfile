# syntax=docker/dockerfile:1

############################################################
# Stage 1: builder — python deps + model weights
############################################################
FROM python:3.14-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements.txt requirements-model.txt ./

# CPU-only torch first: the default PyPI wheel drags in the CUDA stack, which
# is useless on Fargate and multiplies the image size.
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install -r requirements.txt -r requirements-model.txt

# Bake the model weights into the image at build time so cold starts never
# depend on Hugging Face Hub being reachable at runtime.
COPY scripts/download_model.py scripts/download_model.py
ARG MODEL_NAME=fastino/gliner2-privacy-filter-PII-multi
RUN python scripts/download_model.py --model "$MODEL_NAME" --dest /opt/model

############################################################
# Stage 2: runtime
############################################################
FROM python:3.14-slim

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --home-dir /home/app --create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/model /opt/model

WORKDIR /srv
COPY app ./app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MODEL_PATH=/opt/model \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/home/app/.cache/huggingface \
    NUM_THREADS=1

EXPOSE 8000
USER 10001:10001

# Local-dev convenience; in ECS the ALB target-group health check is authoritative.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

# Single uvicorn worker: one copy of the model in memory. See README before
# adding workers — each one loads its own copy of the model.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

# pii-detector

Stateless PII **detection** microservice. It finds PII spans in free text so the
calling workflow (n8n) can tokenize them into per-request placeholders
(`PERSON_1`, `ADDRESS_1`, …) before sending text to OpenRouter/LLM providers,
and later reconstruct the real values.

> ⚠️ **This service does detection only.** It does not tokenize, does not
> reconstruct, and does not persist anything. If you are wiring this into a
> workflow, implement tokenization/reconstruction **on the calling side** — do
> not add it here. Every request is independent: no database, no cache, no
> session.

## How detection works

`POST /detect` runs two detectors and merges their output:

1. **Regex detector** (deterministic, zero inference, `"source": "regex"`,
   confidence always 1.0):
   - `email`
   - `phone_number` — via `phonenumbers` (libphonenumber), not a regex; parses
     international formats plus national formats for the regions in
     `PHONE_REGIONS` (default `US`)
   - `iban` — with mod-97 checksum validation
   - `credit_card` — with Luhn checksum validation
   - `ip_address` — IPv4 and IPv6
   - `api_key` / `secret` / `access_token` — vendor patterns loaded from
     [app/config/secret_patterns.yaml](app/config/secret_patterns.yaml); grow
     the list there, never in code
   - `crypto_wallet_address` — `0x` + 40 hex chars. **Deliberately opt-in**, see
     below.
2. **NER detector** (`"source": "ner"`):
   [`fastino/gliner2-privacy-filter-PII-multi`](https://huggingface.co/fastino/gliner2-privacy-filter-PII-multi)
   (GLiNER2, ~205M params, Apache 2.0) handles free-text labels — `person`,
   `full_name`, `address`, `street_address`, `city`, `organization`, and any
   other label string you pass (GLiNER is zero-shot). Loaded once at process
   startup; weights are baked into the Docker image at build time, so cold
   starts never depend on Hugging Face Hub.

Then two filters:

3. **Denylist** ([app/config/denylist.yaml](app/config/denylist.yaml)): any
   entity whose exact text (case-insensitive) is listed — brand/product names,
   internal agent names — is dropped regardless of confidence. Editable without
   code changes; read once at startup.
4. **Per-label confidence thresholds**: defaults in
   [app/config.py](app/config.py) — `0.7` for `person`/`full_name` (the model
   over-predicts on proper nouns per its own model card), `0.5` for everything
   else — overridable per request.

### ⚠️ `crypto_wallet_address` needs a human decision

In a blockchain product, on-chain addresses are frequently **legitimate
content** (deposit addresses, contract addresses, tx participants), not
incidental PII. Masking them can break the workflows this service protects.
It is therefore **excluded from `DEFAULT_LABELS`**: request it explicitly per
call, or enable it fleet-wide with
`INCLUDE_CRYPTO_WALLET_IN_DEFAULT_LABELS=true` once the team decides wallet
addresses should be treated as PII by default.

## API

### `POST /detect` (requires `X-API-Key` header)

```json
{
  "text": "free text to scan",
  "labels": ["person", "email", "phone_number"],
  "thresholds": {"person": 0.7}
}
```

`labels` and `thresholds` are optional; omitted labels default to
`DEFAULT_LABELS` (see `app/config.py`). Response:

```json
{
  "entities": [
    {"text": "Mario Rossi", "type": "person", "start": 15, "end": 26, "confidence": 0.82, "source": "ner"},
    {"text": "mario@test.com", "type": "email", "start": 40, "end": 54, "confidence": 1.0, "source": "regex"}
  ]
}
```

`start`/`end` are character offsets into the request `text` and always satisfy
`text[start:end] == entity.text` — replace by offsets, not by string search.
Overlapping spans with *different* types are all returned (e.g. a `person`
inside an `address`); the caller decides precedence. Exact duplicates
(same span + type) are deduplicated. Requests are rejected with `413` above
`MAX_TEXT_LENGTH` (default 50k chars); longer texts should be split by the
caller. Missing/wrong API key → `401` with no detection output. `422` responses
never echo the offending input back into logs.

### `GET /health` (no auth — used by the ALB target group)

`200` once the model is loaded and ready; `503` while loading (or if loading
failed). The container starts serving immediately and loads the model in the
background, so orchestrators see an explicit 503 rather than connection
refused.

## Privacy & security invariants

- **No persistence** of any kind. No request state survives the response.
- **No logging of bodies or entity text** — log lines are JSON metadata only:
  request id, method, path, status, latency, per-type entity counts. Keep it
  that way; raw PII in CloudWatch defeats the service's purpose.
- **Auth**: `X-API-Key` compared in constant time against `API_KEY`, which the
  ECS task definition injects from **AWS Secrets Manager** (`secrets` block) —
  never a plain `environment` value, never in Terraform files.
- **CPU-only**: torch installed from the CPU wheel index; `NUM_THREADS` is set
  via `torch.set_num_threads` at startup and Terraform derives it from the task
  CPU size, so torch never assumes the host's core count.
- **Non-root container** (uid 10001).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `API_KEY` | — (required) | Value expected in `X-API-Key`. From Secrets Manager in ECS. |
| `NUM_THREADS` | `1` | torch intra-op threads; keep = task vCPUs (Terraform does this). |
| `LOG_LEVEL` | `INFO` | App log level. |
| `MODEL_PATH` | `/opt/model` | Local model dir (baked into the image). Falls back to `MODEL_NAME` from the Hub if missing (local dev only). |
| `MODEL_NAME` | `fastino/gliner2-privacy-filter-PII-multi` | Hub id used at build time / local fallback. |
| `DENYLIST_PATH` | `app/config/denylist.yaml` | Denylist file. |
| `SECRET_PATTERNS_PATH` | `app/config/secret_patterns.yaml` | Vendor key patterns file. |
| `PHONE_REGIONS` | `US` | Comma-separated regions for national phone formats (e.g. `US,IT,DE`). `+`‑prefixed international numbers match regardless. |
| `MAX_TEXT_LENGTH` | `50000` | Request text cap (chars) → `413` above it. |
| `INCLUDE_CRYPTO_WALLET_IN_DEFAULT_LABELS` | `false` | Opt `crypto_wallet_address` into the defaults (see note above). |
| `NER_WINDOW_CHARS` / `NER_OVERLAP_CHARS` | `1500` / `200` | Long texts are chunked with overlap before NER; offsets are mapped back and duplicates merged. |

Known limitation: if a future `gliner2` release stops returning per-entity
scores, per-label thresholds degrade to the minimum requested threshold applied
inside the model, and reported `confidence` becomes that lower bound. The
adapter (`app/detectors/ner_detector.py`) normalizes the output shapes seen
across gliner/gliner2 releases and is unit-tested against each shape.

## 1. Build and run locally

```bash
docker build -t pii-detector:local .
# Apple Silicon note: the Fargate task is X86_64. For local functional testing
# the native arm64 build above is fine; for the image you push, build amd64:
#   docker buildx build --platform linux/amd64 -t pii-detector:local .

docker run --rm --memory=4g --cpus=1 \
  -e API_KEY=dev-key-change-me \
  -p 8000:8000 \
  pii-detector:local
```

Wait for `/health` to return 200 (first boot loads the model; watch the
`NER model ready` log line and note `load_seconds` — you'll want it for the
health-check grace period). Then:

```bash
curl -s -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-me" \
  -d '{"text": "Hi, I am Mario Rossi, mail me at mario@test.com or call +1 415 555 2671"}' | jq
```

Expected: a `person` entity (`"source": "ner"`) plus `email` and
`phone_number` entities (`"source": "regex"`). Without the header you get 401:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" -d '{"text": "x"}'   # -> 401
```

## 2. Run the tests

The suite mocks the NER model — **torch/gliner2 are never installed for tests**
(that's why the ML stack lives in `requirements-model.txt`, not
`requirements.txt`):

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## 3. Build, tag, push to ECR

```bash
AWS_REGION=eu-west-1
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REPO="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/pii-detector"
TAG=$(git rev-parse --short HEAD)

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker buildx build --platform linux/amd64 -t "$REPO:$TAG" -t "$REPO:latest" --push .
```

Or let CI do it: [.github/workflows/build-push.yml](.github/workflows/build-push.yml)
builds, smoke-tests the image under the production limits
(`--memory=4g --cpus=1`), and pushes on every push to `main` (OIDC auth, no
long-lived AWS keys; actions pinned to full commit SHAs, kept fresh by
Dependabot).

## 4. Deploy with Terraform

Prereqs: an **existing** ECS cluster (the stack never creates one), an ACM
certificate in the target region, a VPC with public subnets (ALB) and
private subnets with NAT or VPC endpoints (tasks), and the image pushed to ECR.

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # edit values
terraform init
terraform plan
terraform apply
```

Then seed the API key **once** (the secret value is deliberately not managed by
Terraform so it never touches code review or state):

```bash
eval "$(terraform output -raw seed_api_key_command)"
```

Tasks that started before the value existed fail with
`ResourceInitializationError` and are retried automatically; the service
converges on its own. Point a DNS record for your certificate's hostname at
`terraform output -raw alb_dns_name`, then:

```bash
curl -s https://pii.example.com/health
```

What the stack creates: task definition (1 vCPU / 4 GB default — validated
against the fixed Fargate CPU/memory pairs at plan time), service with
`desired_count = 2` for zero-downtime rolling deploys, public HTTPS-only ALB
with `/health` target-group checks, security groups (443 from anywhere → ALB;
task port only from the ALB SG), least-privilege IAM (execution role = pull
this one image + read this one secret + write this one log group; task role =
**no permissions**, by design), CloudWatch log group (30-day retention
default), and target-tracking autoscaling on CPU 70% with
`min = desired_count`, `max = max_capacity`.

**Measure the health-check grace period.** The default
`health_check_grace_period_seconds = 60` is a starting point. After the first
deploy, compare the task `startedAt` timestamp with the `NER model ready`
(`load_seconds`) log line, add image-pull time and headroom, and set the
variable accordingly. If tasks get killed as "unhealthy" during startup, this
is the knob.

## 5. Load testing and sizing

Against the local container:

```bash
pip install httpx
python scripts/load_test.py --url http://localhost:8000 --api-key dev-key-change-me -n 200 -c 8
```

Against the deployed service:

```bash
python scripts/load_test.py --url https://pii.example.com --api-key "$API_KEY" -n 500 -c 20
```

Sample output:

```
requests: 200  concurrency: 8  wall: 21.0s  throughput: 9.5 req/s
status counts: {200: 200}  transport errors: 0
latency (ms), HTTP 200 only:
  p50:     780.9
  p95:    1104.2
  p99:    1287.5
  max:    1400.1
```

How to read it and which knob to turn:

- **p50 too high even at `-c 1`** → single-request inference is CPU-bound.
  Raise `cpu` (Terraform keeps `NUM_THREADS` in step automatically). Roughly,
  2× vCPU ≈ meaningfully faster inference until ~4 vCPU.
- **p95 grows sharply as `-c` grows while p50-at-c1 is fine** → requests are
  queueing on one worker. Add tasks: raise `desired_count` (and `max_capacity`)
  rather than making one task bigger — the service is horizontally scalable and
  stateless.
- **Transport errors / 5xx under load** → check service events and CloudWatch;
  if tasks are OOM-killed, raise `memory`. Steady-state RSS is dominated by one
  model copy (~1–1.5 GB); 4 GB has ample headroom for one worker.
- **Throughput target** → `desired_count ≈ target_rps × p50_seconds`, rounded
  up, minimum 2; let autoscaling cover peaks (but remember new tasks take
  cold-start time to arrive — keep min capacity at your steady state).
- `502/503` mixed in during deploys → raise
  `health_check_grace_period_seconds` (see above).

**Workers vs memory:** the container runs a **single uvicorn worker** on
purpose: N workers = N full copies of the model in memory. If you switch to
multiple workers (e.g. gunicorn with uvicorn workers) for more per-task
throughput, multiply task `memory` accordingly (≈ +1.5 GB per extra worker) —
prefer more tasks instead; it's the same money without the deploy-time risk.

## Repository layout

```
app/
  main.py                    # FastAPI app: /detect, /health, auth, metadata-only logging
  schemas.py                 # pydantic request/response models
  config.py                  # DEFAULT_LABELS, thresholds, env parsing
  config/denylist.yaml       # editable never-PII terms (brands, agent names)
  config/secret_patterns.yaml# editable vendor key/token patterns
  detectors/regex_detector.py# email/phone/iban/credit_card/ip/keys/wallets (+ Luhn, mod-97)
  detectors/ner_detector.py  # GLiNER2 singleton, chunking, thresholds, shape adapter
tests/                       # pytest; NER model mocked, no torch needed
Dockerfile                   # multi-stage, CPU-only torch, weights baked in, non-root
scripts/download_model.py    # build-time model snapshot
scripts/load_test.py         # async load test with p50/p95/p99
infra/terraform/             # ECS service, ALB, IAM, secret, autoscaling (existing cluster)
.github/workflows/build-push.yml  # build + smoke test + push to ECR (OIDC, SHA-pinned)
```

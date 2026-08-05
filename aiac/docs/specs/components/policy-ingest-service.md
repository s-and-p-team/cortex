# Component PRD: Policy Ingest Service

## Description
A FastAPI REST service running in its **own** stateless, single-replica pod — the **Policy Ingest Pod** — decoupled from the (stateful) Policy Store Pod that runs ChromaDB. Accepts knowledge documents for any configured collection, chunks and embeds them, and writes the resulting vectors into the **remote** ChromaDB instance in the Policy Store Pod (over `CHROMA_URL`, a cross-pod ClusterIP call). Supports both access control policies (`aiac-policies`) and org/business domain context (`aiac-domain-knowledge`) through a single collection-parameterized API surface. Developer-driven ingestion is performed via `kubectl port-forward`.

Before any document is written to ChromaDB, the service calls the **Policy Validation Agent** module — an **in-process** module in the same pod, not a separate service — to verify it. See [Policy Validation Agent pre-flight verification](#policy-validation-pre-flight-verification) below.

After every successful ingest operation the service publishes a trigger event to the **Event Broker** (NATS JetStream) on the `aiac.apply.policy.build` subject. This causes the AIAC Agent to recompute and apply the updated policy against the live PDP state. All three ingest semantics (replace, update, delete) publish `build`; `rebuild` is an explicit operator-only command issued directly to the Agent and is never triggered by the ingest service.

## Endpoints

The `{collection}` path segment must be a slug from `AIAC_RAG_COLLECTIONS` (default: `policy,domain-knowledge`). Unknown slug → 404.

### Replace — wipe and reload the named collection

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/ingest/{collection}/text` | `{"docs": [{"id": "...", "text": "..."}]}` | Replace entire named collection from a JSON body of text documents |
| POST | `/ingest/{collection}/file` | multipart upload (one or more files) | Replace entire named collection from uploaded files; `doc_id` = filename without extension |
| POST | `/ingest/{collection}/url` | `{"docs": [{"id": "...", "url": "..."}]}` | Replace entire named collection from a JSON body of URLs; service fetches each URL |

**Replace semantics:** drops the ChromaDB collection and recreates it, then ingests all provided documents. Atomic at the collection level — partial failures roll back to an empty collection. An empty `docs` list wipes the collection.

### Update — document-level upsert (additive, never deletes)

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/ingest/{collection}/update/text` | `{"docs": [{"id": "...", "text": "..."}]}` | Upsert documents by `doc_id`; absent `doc_id`s in the collection are left untouched |
| POST | `/ingest/{collection}/update/file` | multipart upload (one or more files) | Upsert documents from uploaded files; `doc_id` = filename without extension |
| POST | `/ingest/{collection}/update/url` | `{"docs": [{"id": "...", "url": "..."}]}` | Upsert documents from URLs; only named `doc_id`s are affected |

**Update semantics:** for each incoming `doc_id`, deletes existing chunks for that `doc_id` then inserts new chunks. All other `doc_id`s in the collection are untouched. An empty `docs` list is a no-op.

### Delete — explicit removal

| Method | Path | Description |
|--------|------|-------------|
| DELETE | `/ingest/{collection}/{doc_id}` | Remove all chunks belonging to `doc_id` from the named collection. `doc_id` not found → 404 |

**Delete** is the only path that removes content from a collection. `/update/*` endpoints never delete as a side effect.

## Policy Validation Agent pre-flight verification

Before writing any document to ChromaDB, the service calls the **in-process** Policy Validation Agent to verify it. This is a **function call**, not an HTTP hop — there is no `:7075` port and no separate service. Full contract: [policy-validation-agent.md](policy-validation-agent.md).

- Applies to all 12 write endpoints above (`replace` and `update`, each across `text`/`file`/`url`), for every collection slug. `DELETE` is exempt.
- One verification call per document. All documents in a request are verified before any ChromaDB mutation for that request occurs.
- **All-or-nothing:** if any document is rejected, the whole request fails and nothing is written to ChromaDB — the collection is left exactly as it was before the request.
- **Fail-closed:** if the validation module **raises** — an unexpected error, or a ChromaDB read it depends on fails — the request is rejected and nothing is written. Validation is **always on** and in-process; there is no operator off-switch (the former `AIAC_GUARDRAILS_ENABLED` bypass is gone).
- **Empty-corpus bootstrap.** Because there is no bypass, the first-ever documents — which have nothing to validate against — must not be deadlocked by the fail-closed, all-or-nothing gate. The `contradiction` check (Check 2) short-circuits to *accept* when its persistent-corpus scan returns **empty**: with no surviving peers there is, by definition, no corpus contradiction, so the seed documents pass on hygiene alone. (Hygiene, Check 1, still applies to every document — bootstrap relaxes only the relational check, never intrinsic quality.) This makes seeding an empty collection a normal `replace`/`update`, needing no special flag.
- This gate does not change the `aiac.apply.policy.build` publish behavior below: it only happens on a successful ingest, so a fail-closed rejection means the event is simply never published for that request.

## Post-ingest Event Broker notification

After every successful ingest operation (replace, update, or delete), the service publishes `{"id": ""}` to `aiac.apply.policy.build` on the Event Broker (`NATS_URL`). The publish is non-blocking: ingest success is reported to the caller before the NATS publish completes. Publish failures are logged but do not cause the ingest endpoint to return an error. This preserves ingest availability even when the Event Broker is temporarily unavailable.

The AIAC Agent's durable consumer receives the event and acknowledges it after successful processing. Delivery guarantees (at-least-once, replay on Agent restart) are managed by the Event Broker — the Policy Ingest Service is fire-and-forget from its perspective.

## Collection slug → ChromaDB name mapping

| Slug | ChromaDB Collection Name |
|------|--------------------------|
| `policy` | `aiac-policies` |
| `domain-knowledge` | `aiac-domain-knowledge` |

## Ingest conventions

- Chunking and embedding are applied uniformly across all operations and both collections.
- `doc_id` is stored in ChromaDB chunk metadata on every write to enable document-level update and deletion.
- `/text` and `/url` endpoints take a JSON body `{"docs": [{"id": "...", "text/url": "..."}]}`.
- `/file` endpoints use multipart upload; `doc_id` is derived from the filename (extension stripped). Filename collisions within one call → 400.

## Configuration

| Variable | Default | Source |
|----------|---------|--------|
| `CHROMA_URL` | `http://aiac-policy-store-service:8000` | ConfigMap |
| `AIAC_RAG_COLLECTIONS` | `policy,domain-knowledge` | ConfigMap |
| `NATS_URL` | `nats://aiac-event-broker-service:4222` | ConfigMap (`aiac-pdp-config`) |
| `EMBEDDING_BASE_URL` | — | ConfigMap |
| `EMBEDDING_MODEL` | — | ConfigMap |
| `EMBEDDING_API_KEY` | — | Kubernetes Secret |

`CHROMA_URL` now points at the **remote** Policy Store Pod (cross-pod ClusterIP), not `localhost` — ChromaDB is no longer co-located. The same URL is used by the in-process Policy Validation Agent for its evaluation-context reads. Policy Validation Agent is in-process and always on, so it contributes **no** `AIAC_GUARDRAILS_*` configuration; its own LLM trio and `VALIDATION_MAX_*` bounds are documented in [policy-validation-agent.md](policy-validation-agent.md).

Adding a third collection is a configuration-only change: add a new slug to `AIAC_RAG_COLLECTIONS` and a corresponding entry in the slug→name map. No code modification required.

## Runtime

- Framework: FastAPI with uvicorn
- Bind: `0.0.0.0:7073`
- Base image: `python:3.12-slim`
- Packaged as the **single `aiac-policy-ingest` image** — there is no separate validation image; the in-process Policy Validation Agent and its LLM/LangGraph dependencies ship inside this one image (one Dockerfile, one `requirements.txt`).

## Dependencies (`requirements.txt`)

The one `requirements.txt` carries **both** the ingest and the in-process Policy Validation Agent dependencies:

```
fastapi
uvicorn[standard]
chromadb
httpx
nats-py
langgraph          # Policy Validation Agent
langchain-openai   # Policy Validation Agent (OpenAI-compatible LLM client)
```

(Embedding model client TBD — depends on chosen embedding provider. Swap `langchain-openai` for the equivalent client if the chosen `LLM_BASE_URL` provider differs.)

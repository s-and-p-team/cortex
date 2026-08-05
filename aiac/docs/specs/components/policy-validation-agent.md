# Component PRD: Policy Validation Agent

## Description

An **in-process Python module** of the Policy Ingest Pod's Policy Ingest Service — **not** a
standalone service. Before any document from an ingest request is written to ChromaDB, the
Policy Ingest Service calls the Policy Validation Agent in-process to obtain a verdict on that
document. There is **no network endpoint**: no `:7075` port, no HTTP hop, no ClusterIP exposure —
validation is a **function call** within the ingest process, so the ingest code is structurally the
only caller. (This property is now absolute: it is not "unexposed on a ClusterIP Service," it is not
on the network at all.)

The module evaluates one document per call. It may query the (now cross-pod) ChromaDB instance in the
Policy Store Pod for evaluation context — including the current (pre-update) version of the same
`doc_id` when one exists — over the same `CHROMA_URL` the ingest process uses for writes.

**One module, two entry points.** The validation code ships **inside** the single `aiac-policy-ingest`
image (its LLM/LangGraph dependencies are folded into that image's `requirements.txt`). It exposes two
independently-developed verification entry points — one for the `policy` collection (`aiac-policies`)
and one for the `domain-knowledge` collection (`aiac-domain-knowledge`). The Policy Ingest Service selects
the entry point by collection slug. **This spec defines the `policy` entry point only**; the
`domain-knowledge` one is specced independently later and mirrors the same wiring and verdict
conventions.

For the `policy` collection the module performs two checks — **policy hygiene** and **contradiction
against the existing corpus** — detailed under [Responsibilities and check set](#responsibilities-and-check-set).
Some aspects of the surface remain unresolved — see [Open decisions (TBD)](#open-decisions-tbd). This
spec fixes the module's place in the architecture, its `policy`-family responsibilities and internal
design, and its contract obligations with the surrounding Policy Ingest Service.

## Module entry points

**Function signatures and verdict object shape TBD** — see [Open decisions (TBD)](#open-decisions-tbd).
The exact Python function signature and the field names of the returned verdict object are unresolved.
What the call **must convey** is fixed, however (see the contradiction decision below): **operation**
(`replace` | `update`), **collection**, **doc_id**, and the document **text**. Because validation is
in-process there is no `/health` endpoint — the module's liveness is the ingest process's own.

## Verification contract

These behaviors are fixed regardless of what the in-process call surface ends up looking like:

- Invoked by the Policy Ingest Service on all 12 write endpoints (`replace` and `update`, each across
  `text`/`file`/`url`) for every collection slug in `AIAC_RAG_COLLECTIONS`. `DELETE
  /ingest/{collection}/{doc_id}` is exempt — removal introduces no new text to verify.
- Called once per document. A multi-document request (a multi-doc `replace` body, or a multipart
  `/file` upload with several files) results in one call per document.
- **Pre-flight**: every document in a request is validated before the Policy Ingest Service makes any
  ChromaDB mutation for that request.
- **All-or-nothing**: if any document in a request is rejected, the whole ingest request fails and
  nothing is written — the collection is left exactly as it was. This preserves the Policy Ingest
  Service's existing collection-level atomicity guarantee for `replace`.
- **Fail-closed**: if the validation module **raises** (an unexpected error, or a ChromaDB read it
  depends on fails), the Policy Ingest Service treats that as a rejection and writes nothing. Fail-closed
  now means "the validation module raised → the request is rejected," not "a remote agent was
  unreachable." Validation is **always on** — there is no operator off-switch (the former
  `AIAC_GUARDRAILS_ENABLED` bypass is gone). The **empty-corpus bootstrap** path that keeps the
  first-ever documents from deadlocking against the fail-closed gate is defined in
  [policy-ingest-service.md](policy-ingest-service.md#policy-validation-pre-flight-verification).
- No Event Broker interaction. The module neither publishes nor consumes NATS subjects. The Policy
  Ingest Service's existing `aiac.apply.policy.build` publish behavior is unchanged: a fail-closed
  rejection means the ingest request never succeeds, so the build event is simply never published for
  that request.

## Responsibilities and check set

The `policy` entry point runs two checks against a single incoming `aiac-policies` document. Both are
LLM-backed (hygiene and contradiction over natural-language policy are inherently semantic).

### Check 1 — Policy hygiene (intrinsic; single document, no corpus)

> **Detailed design:** [policy-validation-agent-policy-hygiene.md](policy-validation-agent-policy-hygiene.md) — the
> finding-code taxonomy, severity derivation, pre-LLM guards, and structured-output contract for this
> check.

Three facets of the document's intrinsic quality:

- **On-topic & well-formed** — the document must actually express access-control intent (some
  subject/role → service/scope/action). Empty, gibberish, or off-topic text is rejected.
- **Actionable / translatable** — the statement must be specific enough for the downstream AIAC Agent
  LLM to emit Rego: it references resolvable roles/services/scopes/actions and avoids hopeless
  vagueness ("be secure", "do the right thing").
- **Internally consistent & clear** — the document does not contradict *itself* and is not so
  ambiguous it would yield nondeterministic Rego. (Self-contradiction; distinct from corpus
  contradiction below.)

Prompt-injection / adversarial-content screening is **out of scope for this increment** (deferred; it
was always a separate concern from hygiene).

### Check 2 — Contradiction against the existing corpus (relational)

Whether the incoming document conflicts with policy already in the collection. The baseline is **the
persistent corpus only** — what will still exist after the write:

- **`update`** → the incoming document is compared against the persistent ChromaDB corpus (all
  documents that survive the upsert), **excluding this `doc_id`'s own prior version**. Replacing a
  document with a reversed policy is a legitimate change, not a contradiction, so the prior version is
  never treated as a conflicting peer.
- **`replace`** → **no** corpus-contradiction check. `replace` drops and recreates the collection,
  redefining it atomically; the pre-write corpus is about to be deleted, so flagging a conflict
  against soon-to-be-removed documents would be wrong. `replace` documents receive hygiene (including
  internal self-consistency) only.
- **Intra-batch contradiction** (one document in a request conflicting with a *sibling* document in
  the same request) is **not** detected in this increment — a documented deferral for both operations.
  Because validation is one-call-per-document and pre-flight, sibling documents are not yet in ChromaDB
  and are not passed in the call.

This is why the validation call must convey the **operation** and **collection**: the module cannot
otherwise interpret ChromaDB contents correctly (a `replace` reading the pre-write corpus would produce
false contradictions).

## Module design

Built on **LangGraph** to match the AIAC Agent stack. A `StateGraph` runs the checks staged, with a
short-circuit so a failed hygiene check never triggers an unnecessary corpus scan or contradiction LLM
call.

**Graph state** (per verification call): the input document (`text`, `doc_id`), `operation`,
`collection`, the fetched `corpus` (populated only for `update`), the accumulated `findings`, and the
final `verdict`.

**Nodes and edges:**

```
        ┌──────────┐
 in ──► │ hygiene  │  (1 LLM call; no corpus)
        └────┬─────┘
             │ any blocking hygiene finding
             ├───────────────────────────────► verdict   (short-circuit)
             │ hygiene clean
             ▼
      operation == update ? ──── no (replace) ──► verdict
             │ yes
             ▼
        ┌──────────────┐      ┌───────────────┐
        │ corpus_fetch │ ───► │ contradiction │ ──► verdict
        └──────────────┘      └───────────────┘   (1 LLM call)
```

- **`hygiene`** — one LLM call judging the three hygiene facets; emits findings.
- Conditional edge — if hygiene produced any *blocking* finding, jump straight to `verdict` (judging
  contradiction on malformed text is noise and wastes a corpus scan). Otherwise, if `operation ==
  update`, proceed to `corpus_fetch`; if `operation == replace`, jump to `verdict`.
- **`corpus_fetch`** — **full-corpus scan**: `.get()` all documents in the collection from ChromaDB
  (no similarity search, so the module needs no embedding-API dependency), regroup chunks by `doc_id`,
  and drop this document's own prior version. A full scan catches logically-opposed-but-dissimilar
  contradictions ("admins may delete anything" vs "production is immutable") that top-K retrieval would
  miss. Guarded by `VALIDATION_MAX_CORPUS_DOCS` — see [Corpus-scan guard](#corpus-scan-guard).
- **`contradiction`** — one LLM call judging the incoming document against the fetched corpus; emits
  findings naming the conflicting `related_doc_id`.
- **`verdict`** — aggregates findings into the final verdict (see below).

### Findings and verdict model

Each check emits structured findings: `{check, severity, message, related_doc_id?}` where `severity ∈
{blocking, advisory}`.

- **Verdict = reject** iff at least one **blocking** finding is present; otherwise **accept**.
- **Advisory** findings are returned but never block — a non-fatal channel so the LLM can flag concerns
  without failing the operator's whole ingest request (recall all-or-nothing).
- The LLM is instructed which conditions are blocking (not-a-policy, untranslatable, self-contradiction,
  corpus-contradiction) vs advisory (style, redundancy, minor vagueness).

LLM structured output is obtained via the LangChain structured-output surface (e.g.
`with_structured_output`) so findings are validated at the call boundary.

### Corpus-scan guard

`VALIDATION_MAX_CORPUS_DOCS` bounds the full-corpus scan. If the collection exceeds the limit, the
`corpus_fetch` / `contradiction` path **fails-closed** (the module raises, which the Policy Ingest Service
treats as a rejection), consistent with the module's fail-closed posture. This keeps a large corpus
from silently degrading to partial or truncated contradiction coverage.

## Configuration

The module reads its configuration from the Policy Ingest Pod's own environment (it shares the ingest
process), not from a separate service ConfigMap:

| Variable | Default | Source |
|----------|---------|--------|
| `CHROMA_URL` | `http://aiac-policy-store-service:8000` | ConfigMap (Policy Ingest Pod) — shared with the ingest write path |
| `LLM_BASE_URL` | — | ConfigMap |
| `LLM_MODEL` | — | ConfigMap |
| `LLM_API_KEY` | — | Kubernetes Secret |
| `VALIDATION_MAX_CORPUS_DOCS` | `500` | ConfigMap |

`LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` reuse the existing AIAC LLM convention (same trio the AIAC
Agent and integration tests use). There are **no** `AIAC_GUARDRAILS_*` variables on the Policy Ingest
Service side — validation is in-process and always on, so there is no URL, enable-flag, or timeout to
configure.

## Runtime

- Runs **in-process** inside the Policy Ingest Service (the `aiac-policy-ingest` image); no separate
  process, port, or bind address.
- LangGraph/LLM dependencies are carried in the single `aiac-policy-ingest` image (see
  [Dependencies](#dependencies)); it runs as non-root UID 10001 per the AIAC container pattern along
  with the rest of that image.

## Dependencies

The validation module's dependencies are folded into the **single** `aiac-policy-ingest` image's
`requirements.txt` (alongside the ingest dependencies). The validation-specific additions are:

```
langgraph
langchain-openai
```

(`chromadb` and `httpx` are already required by the ingest side. `langchain-openai` is the
OpenAI-compatible LLM client for the LangGraph nodes; swap for the equivalent client if the chosen
`LLM_BASE_URL` provider differs.)

## Open decisions (TBD)

1. **Call surface and verdict object shape** — the Python function signature(s) of the entry points
   and the field names of the returned verdict object. The *information* the call must carry
   (operation, collection, doc_id, text) and the verdict/findings *model* (accept/reject +
   two-level-severity findings) are fixed above; only the in-process representation is open.
2. **Strictness calibration** — how conservative the hygiene/contradiction prompts are about emitting
   *blocking* (vs advisory) findings, given that one false blocking finding fails the operator's whole
   request.
3. **Findings persistence** — whether rejection findings are only returned synchronously to the caller
   (plus structured logging), or also persisted somewhere for audit. Deferred this increment:
   synchronous return + stdout logging only.
4. **Operator override** — whether an operator can force-accept a rejected document, and through what
   path. Deferred this increment: there is no override — validation is always on and in-process.
5. **`domain-knowledge` entry point** — the second verification entry point (factual-coherence /
   contradiction for `aiac-domain-knowledge`) is specced independently later.

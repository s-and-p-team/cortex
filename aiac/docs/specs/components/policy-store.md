# Component PRD: Policy Store

## Description
A ChromaDB vector store that holds two named collections in a single instance: AIAC access control policies (`aiac-policies`) and org/business domain context (`aiac-domain-knowledge`). It is the **source-of-truth natural-language policy** store, deployed as its **own dedicated pod** — the **Policy Store Pod** — decoupled from the (stateless) Policy Ingest Pod for lifecycle and resource isolation. The AIAC Agent retrieves relevant chunks from both collections at runtime via similarity search. The **Policy Validation Agent** module — in-process in the Policy Ingest Pod — also reads from ChromaDB across the cluster, for evaluation context, as part of its pre-flight verification of documents the Policy Ingest Service is about to write (see [policy-validation-agent.md](policy-validation-agent.md)).

## Technology
ChromaDB

## Collections

| Slug (wire) | ChromaDB Collection Name | Content | Written by | Read by |
|-------------|--------------------------|---------|------------|---------|
| `policy` | `aiac-policies` | Access control policy rules in natural language | Policy Ingest Service | Agent `fetch_policy` node |
| `domain-knowledge` | `aiac-domain-knowledge` | Org/business context — team rosters, application ownership, department mappings, who-does-what | Policy Ingest Service | Agent `fetch_domain_knowledge` node |

The legal collection set is an open extension point governed by `AIAC_RAG_COLLECTIONS` on the Policy Ingest Service. Adding a new collection is a configuration-only change (new slug + ChromaDB name in the slug→name map) with no code modification required.

## Deployment
Its own dedicated Kubernetes **StatefulSet** `aiac-policy-store` (the Policy Store Pod) — **no longer co-located** with the Policy Ingest Service or Policy Validation Agent. Exposed via the `aiac-policy-store-service` ClusterIP Service on port 8000 (ChromaDB default), with a headless `aiac-policy-store-headless` Service for stable pod DNS. Manifest: `policy-store-statefulset.yaml`.

ChromaDB runs with `IS_PERSISTENT=TRUE` and `PERSIST_DIRECTORY=/chroma/chroma`. Data is stored on a 1 Gi `ReadWriteOnce` PersistentVolumeClaim mounted at `/chroma/chroma`. On pod recreation the StatefulSet rebinds the same PVC; ChromaDB resumes from persisted state without re-ingestion. The Policy Store Pod runs as a single replica.

## Access patterns

| Consumer | Operation | Collection |
|----------|-----------|------------|
| Policy Ingest Service | Write (replace / upsert / delete) | Either collection, selected by `{collection}` slug in the request URL |
| Policy Validation Agent (in the Policy Ingest Pod) | Read (evaluation context, e.g. the pre-update version of a `doc_id`) | Either collection, matching the document under verification |
| AIAC Agent `fetch_policy` | Read (similarity search, top-N chunks) | `aiac-policies` |
| AIAC Agent `fetch_domain_knowledge` | Read (similarity search, top-N chunks) | `aiac-domain-knowledge` |

Each chunk written to ChromaDB stores `doc_id` in its metadata to enable document-level upsert and targeted deletion.

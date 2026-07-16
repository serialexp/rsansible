# rsansible run push protocol (v1)

`rsansible run --report-url <BASE>` streams a run's per-`(host, task)` results to
an HTTP ingestion endpoint *as tasks finish*, so a run is observable live and a
controller that dies mid-run leaves a persisted **partial** on the server.

This protocol is **vendor-neutral**. rsansible knows nothing about any particular
server; any service that implements the four endpoints below can consume runs.
The reporter lives in `crates/ctl/src/report_http.rs`; the wire types there are the
normative Rust definitions of everything documented here.

## Model

- **namespace / project / stack** identify where a run is recorded. `project` is
  the playbook/repo scope; `stack` is the target environment/inventory (`prod`,
  `staging`); the run belongs to a namespace/org.
- **one `rsansible` invocation = one run.**
- An **item** is one `(task, host)` result. Its `dimensions` map carries the
  pivot coordinates (`host`, `task`, and `play`/`role` when known) so a consumer
  can group a run by host or by task over the same rows.
- A run is opened with an **operator token** (`Bearer`), which mints a per-run
  **lease token**. Every streaming write after `open` authenticates with the
  lease, not the operator token. The lease is renewable; a consumer times a run
  out if renewals stop (dead controller).

## Endpoints

All request/response bodies are JSON. `{base}` is the `--report-url` value with
any trailing slash stripped.

### `POST {base}/runs` — open

`Authorization: Bearer <operator-token>`

```json
{ "namespace": "acme", "project": "site", "stack": "prod",
  "mode": "apply", "playbook": "site.yml", "inventory": "prod" }
```

`mode` is `"apply"` (a real converge) or `"check"` (a `--check` dry run, stored
identically but flagged). `playbook`/`inventory` are optional display hints.

Response:

```json
{ "run_id": "…", "lease_token": "…",
  "lease_expires_at": "2026-07-16T12:00:00Z", "renew_interval_secs": 240 }
```

The server lazily creates the project/stack if absent and opens a running record.

### `POST {base}/runs/{run_id}/items` — ingest (batched, idempotent)

`Authorization: Bearer <lease-token>`

```json
{ "items": [
  { "sequence": 0,
    "dimensions": { "host": "db-1", "task": "install patroni", "play": "converge" },
    "name": "install patroni", "status": "changed", "changed": true,
    "rc": 0, "started_at": "…", "finished_at": "…",
    "diff": "{\"before\":\"…\",\"after\":\"…\",\"before_header\":\"…\",\"after_header\":\"…\"}" }
] }
```

- `status` ∈ `ok | changed | skipped | failed | unreachable`.
- `sequence` is monotonic within the run.
- Items are **upserted keyed by `(run, dimensions)`** — re-sending a batch after a
  transient failure must not duplicate rows.
- `diff`, when present, is an Ansible-shaped `{before, after, before_header,
  after_header}` payload (or a JSON array of those for a looped task), serialized
  as a string. The server stores it verbatim and associates it with the item; it
  computes nothing from it. `sequence` doubles as the item's diff-event id.
- `error` is present only for `failed`/`unreachable`.

### `POST {base}/runs/{run_id}/finalize` — finalize

`Authorization: Bearer <lease-token>`

```json
{ "status": "succeeded",
  "summary": { "ok": 10, "changed": 3, "skipped": 1, "failed": 0, "unreachable": 0 },
  "stopped_early": false }
```

`status` ∈ `succeeded | failed`. Sets the run's terminal state and counts.

### `POST {base}/runs/{run_id}/renew` — renew lease

`Authorization: Bearer <lease-token>` → `{ "lease_expires_at": "…" }`

The client renews every `renew_interval_secs`. Missed renewals let the server
time the run out.

## Client behaviour (normative)

- `open` happens up front; a failure aborts the run before any host is dialled.
- Items are buffered and flushed on a size or time threshold. A failed `items` or
  `finalize` POST is retried with backoff; the buffer is **retained** across
  failures so a network blip never loses a run.
- A reporting error is never fatal to the converge — a failed push must not flip
  an otherwise-successful run's exit code.

## Versioning

This is protocol **v1**. Fields are added compatibly (new optional fields;
consumers ignore unknown fields). A breaking change bumps the version and the
base path.

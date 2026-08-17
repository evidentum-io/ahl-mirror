# ahl-mirror

An independent mirror for the [AHL Protocol](https://atl-protocol.org)'s `ahl-adaptor-atl-v1`
profile: byte-exact retrieval by entry id, authenticated range enumeration, and the canonical
checkpoint series a corpus needs to reach conformance level L3 on an ATL-backed log.

## Why this exists

The AHL core specification's log-binding contract (core spec §3) requires two interfaces a
stock ATL deployment does not serve:

- **retrieval of an entry's bytes by AHL entry id** (contract item 4) — ATL's own receipt
  carries a digest of the envelope, never the envelope itself (adaptor profile §10.1.1);
- **authenticated range enumeration** with proof of completeness and order (contract item 5)
  — the published `atl-server` HTTP surface has no route for it at all (adaptor profile
  §10.1, §15).

At conformance level L3 both MUST be available from a party **outside the producer's
control** (core spec §3.5). `ahl-mirror` is that party. It stores entry bytes as they are
anchored, checks everything it can check before storing or serving anything, and answers
retrieval and range requests with proofs a verifier can check entirely offline against a
signed checkpoint.

## What this crate is not

It does not interpret AHL statement payloads, does not walk the statement graph (inputs,
outputs, triggers, closure), does not verify producer signatures, and does not know about the
AHL manifest chain. Those are a verifier's job (core spec §6) and a producer's job
respectively. This crate's entire contract is: bytes in, byte-exact bytes out, with proofs
the log-tree math backs.

## Architecture

A library (`src/lib.rs` and siblings) plus a thin binary (`src/bin/ahl-mirror.rs`):

| module | responsibility |
| --- | --- |
| `metadata` | the fixed ATL adaptor metadata object (§4.2) and the log-tree leaf hash |
| `store` | durable storage — entries by id and index, the checkpoint series |
| `ingest` | the five checks a submitted entry must pass before it is stored |
| `retrieval` | retrieval by entry id (§10.1.1), with a defensive re-hash before serving |
| `range` | range-proof generation, `AHLRP1` serialization, and offline verification |
| `checkpoint` | checkpoint parsing/signing, `ITUB`, series admission and consistency |
| `config` | the log and trusted checkpoint-signing keys this deployment trusts |
| `http` | an `axum` router — thin handlers over the modules above, nothing more |

Every business rule is a plain function tested directly, without HTTP in the loop; the HTTP
layer's own tests check wiring (status codes, byte-exactness, request/response shapes), not
the rules themselves.

### Reuse, not reimplementation

Canonicalization (JCS/RFC 8785), family-string parsing, envelope and checkpoint identifiers,
and range-proof generation/verification are reused from `ahl-core`
(`ahl-core = { path = "../ahl-core" }`) rather than reimplemented — the same anti-drift
discipline `ahl-core` itself follows against `atl-core`. This crate calls `atl-core`'s Merkle
primitives directly, at the same pinned revision `ahl-core` depends on, only where `ahl-core`
does not expose them: RFC 9162 consistency proofs, and the ATL-specific log-leaf construction
of adaptor profile §4.2 (`SHA-256(0x00 || payload_hash || metadata_hash)`), which is
deliberately different from the plain AHL tree leaf hashing `ahl-core` uses for
batch/input-set/disposition trees (adaptor profile §9's "deliberate asymmetry").

## Storage decision

A single-file `SQLite` database (`rusqlite`, `bundled` feature — no server process, no system
`SQLite` dependency). Two tables: `entries(entry_index PRIMARY KEY, entry_id UNIQUE,
envelope)` and `checkpoints(tree_size PRIMARY KEY, log_id, root_hash, checkpoint_time,
key_id, signature)`. Entries are content-addressed by `entry_id` (unique) and indexed by
`entry_index` (primary key); the checkpoint table's primary key doubles as the ordering
`ITUB` needs.

`SQLite` was chosen over a plain content-addressed directory because the mirror needs three
things a directory does not give for free: an atomic, crash-safe link between "this index"
and "these exact bytes" (ingest can never leave a torn write behind); an efficient "smallest
`tree_size` strictly greater than `i`" query for `ITUB` (adaptor profile §5.2.1); and an
efficient contiguous-range scan for enumeration (§10.3). One file, one dependency, no server
— which is what the brief's "simple durable local store" asks for.

Concurrency: all access is serialized behind one connection and one mutex, with every query
run inside `tokio::task::spawn_blocking` so a slow database call never stalls the async
runtime. A mirror is read-heavy and single-writer by construction — one producer, one log,
per adaptor profile §3 — so this is a correctness simplification, not a throughput
compromise for the intended workload, and is worth revisiting first if this ever needs to
serve many concurrent writers.

## What is implemented

- **Ingest** (task item 1): §2.1/§2.4/§4.2 checks in order — bytes hash to the claimed entry
  id; parse as JSON; envelope-shaped (`payload` object, non-empty `signatures` array — core
  spec §2.1: unsigned objects are not AHL statements); JCS-canonical round-trip; ATL metadata
  equals the fixed adaptor object. Each failure is a distinct `MirrorError` variant. Ingest is
  idempotent for a byte-identical repeat at the same index and append-only otherwise (a gap
  or a conflicting occupant is rejected).
- **Retrieval by entry id** (task item 2; adaptor profile §10.1.1): exactly the semantics
  specified — present returns the stored bytes unaltered (raw `application/json`, or a
  `base64:` text form via `?encoding=base64`), absent is a 404 with an explicit note that
  absence is a fact about the interface, never evidence of non-existence. A defensive re-hash
  runs before any bytes leave the store.
- **Authenticated range enumeration** (task item 3; adaptor profile §10.2-§10.5): the request
  shape of §10.3, the `AHLRP1` proof exactly as serialized in §10.5 (reusing
  `ahl-core::range_proof` for the tree math, with the ATL log-leaf construction of §4.2 as
  input), and an offline `verify_range_response` that replays what a receiving verifier does.
  `build_range_response` never serves a proof it has not itself verified first.
- **Checkpoint series** (task item 4; adaptor profile §5.2.2): checkpoints are verified
  (`log_id`, signature, optional `raw` blob per §6.4) and admitted only if the mirror's
  stored entries for `[0, tree_size)` are complete and recompute to the claimed root, and —
  once a predecessor exists — only if a generated RFC 9162 consistency proof from the
  predecessor to the new checkpoint verifies. `ITUB(i)` (§5.2.1) is a pure function over the
  series. Consistency proofs between any two series members are served on request
  (`GET /v1/consistency?from=&to=`) wherever the backing entries are held.
- **Storage** (task item 5): see above.

## Where the profile was ambiguous or under-specified

Reported as asked, for the next specification round — not papered over.

1. **Who authenticates an incoming checkpoint, and against what key state?** Adaptor profile
   §7.3 resolves a checkpoint-signing key against "the manifest version active for the
   checkpoint's `tree_size`" — but a mirror, by design (see "What this crate is not"), has no
   access to the AHL manifest chain. The profile does not say how a standalone mirror
   component is supposed to authenticate the checkpoints it is asked to publish as canonical.
   This crate resolves the gap with a small operator-configured trust set
   (`Config`/`TrustedLogKeySpec`, shaped like the manifest's log key objects but populated by
   deployment configuration, not by walking a chain) and does **not** implement key
   currency/rotation via `valid_from_index` — the field is carried through for shape parity
   and otherwise ignored. A real deployment with rotating log keys needs either a
   manifest-aware sidecar feeding this crate's trust set, or the profile defining a
   mirror-appropriate authentication path that does not presuppose manifest access.
2. **What discharges "gap-free" for a component that only stores entries, not manifests?**
   Adaptor profile §5.2.2 item 1 defines gap-free as "a consistency proof from its
   predecessor is available". Given this crate's storage model — one append-only sequence of
   entries, both checkpoints' roots independently recomputed from it before the consistency
   check runs — a consistency proof between two individually-verified checkpoints over the
   same store is mathematically guaranteed to exist and verify; the explicit consistency
   check in `checkpoint::ingest_checkpoint` is therefore redundant *given this storage
   model*, not vacuous in general. The profile does not distinguish "gap-free by
   construction of the storage" from "gap-free by an independent proof check" as compliance
   arguments, and a future storage backend that does not hold the full leaf sequence (e.g. a
   federation of partial mirrors) would need the check to do real work. Kept the check anyway
   — it is cheap, and it is the only thing that would catch a defect in a future storage
   backend that stops being a single source of truth.
3. **§10.1.1's "MAY additionally carry the entry index and an inclusion proof"** is optional
   ("MAY") and this crate does not implement it on the plain retrieval path — only the range
   endpoint returns proofs. A caller wanting an inclusion proof for a single entry can request
   a width-1 range (`from_index = i, to_index = i + 1`), which the profile itself notes "is
   an inclusion proof in another serialization" (§10.4). Documented as a deliberate scope
   choice, not an oversight.
4. **Consistency-proof serialization for the standalone `GET /v1/consistency` endpoint** is
   this crate's own invention — the profile fixes `AHLRP1` for range proofs (§10.5) and the
   receipt format's `consistency_path` shape (§8.3: a JSON array of `sha256:<hex>` strings)
   but does not define a request/response envelope for fetching a bare consistency proof
   outside a receipt. This crate uses the §8.3 array form for the path and a small ad hoc
   JSON wrapper around it; not profile-normative, and named as such.

## Quick start

```bash
cargo build --release
```

Configuration is a JSON file matching `ConfigSpec`:

```json
{
  "log_id": "sha256:<hex Origin ID>",
  "keys": [
    { "key_id": "sha256:<hex>", "pubkey": "base64:<32 raw bytes>", "valid_from_index": 0 }
  ],
  "store_path": "/var/lib/ahl-mirror/mirror.sqlite3"
}
```

```bash
ahl-mirror --config mirror.json --listen 127.0.0.1:8080
```

## HTTP surface

| method | path | purpose |
| --- | --- | --- |
| `POST` | `/v1/entries` | ingest one entry (§4.2 checks; JSON body, envelope carried base64) |
| `GET` | `/v1/entries/{entry_id}` | retrieval by entry id (§10.1.1); `?encoding=base64` for the text form |
| `POST` | `/v1/range` | authenticated range enumeration (§10.2-§10.5) |
| `POST` | `/v1/checkpoints` | admit a checkpoint into the canonical series (§5.2.2) |
| `GET` | `/v1/checkpoints` | the full canonical series |
| `GET` | `/v1/checkpoints/{tree_size}` | one series member |
| `GET` | `/v1/itub/{index}` | `ITUB(index)` (§5.2.1) |
| `GET` | `/v1/consistency?from=&to=` | a consistency proof between two series members |
| `GET` | `/health` | liveness |

None of this wire shape is normative except where it carries profile-defined material
(`range_proof.adaptor_form`, the checkpoint object, `consistency_path`) — the request/response
envelopes around them are this crate's own, chosen for a small, obvious REST surface.

## Quality gates

MSRV 1.92, edition 2021. `cargo build --all-targets`, `cargo test`, `cargo clippy
--all-targets --all-features -- -D warnings`, and `cargo fmt --all -- --check` all pass with
zero warnings. `cargo llvm-cov --all-features --ignore-filename-regex 'src/bin/'
--fail-under-lines 90` passes; `src/bin/` is excluded as thin process wiring (config load,
socket bind, graceful shutdown) exercised by hand rather than by unit tests, matching
`ahl-core`'s convention for its own `src/bin/`. No `unwrap`/`expect`/`panic` in library code
paths (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]` in `lib.rs`
and the binary; test code is exempted via `#![cfg_attr(test, allow(...))]`, since tests are
not library code paths). No `unsafe` (`#![forbid(unsafe_code)]`).

Tests are deterministic: no wall-clock reads, no randomness. Checkpoint times, Ed25519 test
keys, and entry contents are all fixed values.

## License

Apache-2.0. See `LICENSE`.

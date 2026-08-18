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

**The service never lets whoever talks to it determine its own state.** An entry becomes
retrievable/enumerable only once it carries a Merkle inclusion proof against a checkpoint
this mirror has itself authenticated — never on the strength of a submitted claim alone.
Checkpoint-signing keys are resolved from a **verified governance chain** — every
`manifest`/`key` statement counted only once its producer signature verifies and, for a
non-genesis manifest, its `predecessor` link is confirmed — walked from a configured genesis
anchor, never from an anchored-but-unverified statement's say-so. A checkpoint is
**authenticated** on signature alone and **series-usable** — the only state that may ground
an incorporation-time bound, an enumeration response, or a completeness claim — only once its
root and neighbour consistency are independently confirmed. And the checkpoint series tracks
whether it is *provably* gap-free at the cadence each governing manifest version declares,
reporting `ITUB` as unavailable rather than guessing wherever it is not. See "What is
implemented" below for the detail.

## What this crate is not

It does not walk the statement graph (inputs, outputs, triggers, closure) and does not
interpret dataset, pipeline, or retention semantics — those are a verifier's job (core spec
§6). The one exception is the `manifest` module: it verifies the governance chain itself
(producer signatures, `predecessor` linkage), because core spec §7.3 makes that verification
a prerequisite for resolving a checkpoint-signing key at all, not an optional extra a mirror
can skip.

## Architecture

A library (`src/lib.rs` and siblings) plus a thin binary (`src/bin/ahl-mirror.rs`):

| module | responsibility |
| --- | --- |
| `metadata` | the fixed ATL adaptor metadata object (§4.2) and the log-tree leaf hash |
| `duration` | ISO 8601 duration parsing for `checkpoint_cadence`/`witness_grace_period` |
| `store` | durable storage — staged and canonical entries, the authenticated checkpoint set |
| `ingest` | the format checks a submitted entry must pass to be staged, and proof-gated promotion to canonical storage |
| `manifest` | the verified governance chain walk: producer-signature and `predecessor` checks, checkpoint-signing key and cadence resolution |
| `retrieval` | retrieval by entry id (§10.1.1), with a defensive re-hash before serving |
| `range` | range-proof generation, `AHLRP1` serialization, and offline verification |
| `checkpoint` | checkpoint parsing/signing, the authenticated/series-usable state machine, gap-free-frontier computation, `ITUB` |
| `config` | the log this mirror serves and the genesis governance anchor it bootstraps from |
| `http` | an `axum` router — thin handlers over the modules above, nothing more |

Every business rule is a plain function tested directly, without HTTP in the loop; the HTTP
layer's own tests check wiring (status codes, byte-exactness, request/response shapes), not
the rules themselves.

### Reuse, not reimplementation

Canonicalization (JCS/RFC 8785), family-string parsing, envelope and checkpoint identifiers,
range-proof generation/verification, and envelope signature verification (`verify_envelope`,
reused as-is for governance statements' producer signatures) are all reused from `ahl-core`
(`ahl-core = { path = "../ahl-core" }`) rather than reimplemented — the same anti-drift
discipline `ahl-core` itself follows against `atl-core`. This crate calls `atl-core`'s Merkle
primitives directly, at the same pinned revision `ahl-core` depends on, only where `ahl-core`
does not expose them: RFC 9162 consistency proofs, RFC 6962 inclusion-proof generation, and
the ATL-specific log-leaf construction of adaptor profile §4.2
(`SHA-256(0x00 || payload_hash || metadata_hash)`), which is deliberately different from the
plain AHL tree leaf hashing `ahl-core` uses for batch/input-set/disposition trees (adaptor
profile §9's "deliberate asymmetry").

## Storage decision

A single-file `SQLite` database (`rusqlite`, `bundled` feature — no server process, no system
`SQLite` dependency). Three tables:

- `staged_entries(entry_id PRIMARY KEY, envelope)` — content-addressed only, **not**
  index-exclusive: any number of candidates for the same position may sit here without
  blocking each other.
- `entries(entry_index PRIMARY KEY, entry_id UNIQUE, envelope)` — canonical, position-indexed;
  a row lands here only via a verified Merkle inclusion proof.
- `checkpoints(id AUTOINCREMENT, tree_size, log_id, root_hash, checkpoint_time, key_id,
  signature, UNIQUE(tree_size, checkpoint_time))` — every *authenticated* checkpoint (core
  spec §7.3). `tree_size` alone is **not** the key: core spec §7.3 requires a quiet log —
  one receiving no new entries — to keep publishing checkpoints at unchanged `tree_size`, so
  the same size legitimately recurs with a later `checkpoint_time`; both are needed to
  identify one member. Series-usability is never stored here — it is computed on demand (see
  "Verification states" below), because it can change as entries arrive after a checkpoint
  does.

`SQLite` was chosen over a plain content-addressed directory because the mirror needs three
things a directory does not give for free: an atomic, crash-safe link between "this index"
and "these exact bytes" so promotion can never leave a torn write behind; efficient ordered
scans over the checkpoint set for gap-free-frontier computation; and an efficient
contiguous-range scan for enumeration (§10.3). One file, one dependency, no server — which is
what the brief's "simple durable local store" asks for.

Concurrency: all access is serialized behind one connection and one mutex, and every query
still runs inside `tokio::task::spawn_blocking` so a slow database call never stalls the async
runtime. Admission has two phases: building the visible entry prefix, resolving governance,
and verifying the checkpoint's signature are read-only and run first; promoting every entry in
the batch and recording the checkpoint itself are writes, and run inside one `SQLite`
transaction (`Store::with_transaction`), so a batch that fails partway — a bad inclusion proof
on the last of several `entries_to_promote`, say — leaves the store exactly as it was before
the request, never partially admitted. A mirror is single-writer by construction (one
producer, one log, per adaptor profile §3), so cross-request transactions on top of this are
not needed.

## What is implemented

- **Ingest, split into staging and evidence-gated promotion** (adaptor profile §4.2, §8.2;
  unchanged in shape from the first round). `ingest::stage_entry` runs the format checks and
  stores the result in `staged_entries`, which carries **no** claim about position or
  anchoring. `ingest::promote_entry` is the only path into canonical storage, gated on a
  Merkle inclusion proof against an authenticated checkpoint's claimed root.
- **A verified governance chain, not "anchored, therefore trusted"** (core spec §7.3,
  "Governance statements are not self-authorizing"). `manifest::resolve` walks entries from
  index 0, and a `manifest`/`key` statement counts as governance only if: it is the
  **genesis** manifest, whose entry id matches `Config::genesis_manifest_entry_id` and whose
  producer signature verifies under `Config::genesis_producer_keys` (the out-of-band trust
  anchor, core spec §2.3.5); or it is a **non-genesis** manifest whose `predecessor` names the
  currently active version's entry id and whose producer signature verifies under *that*
  version's current producer key set, with `log.cadence_epoch` unchanged from genesis (a
  later version declaring a different epoch is treated as malformed, per core spec §7.3); or
  it is a `key` statement whose producer signature verifies under the producer key set
  currently in force, which then adds or retires a producer key going forward. A statement
  failing its check is simply not governance — skipped, with the walk continuing from the
  last genuinely verified state — never a reason to abort resolution outright.
- **Bootstrap ordering that lets a checkpoint's own range carry the governance it needs to
  verify itself.** Signature verification for a checkpoint happens *after* building a visible
  entry prefix that overlays canonical storage with any `entries_to_promote` whose inclusion
  proof verifies against the checkpoint's *claimed* root (safe to inspect before that root is
  authenticated: the proof only ties bytes to a position *within* the claimed tree, it does
  not assert the claim is genuine). A manifest rotation anchored in the very batch a
  checkpoint is admitting can therefore resolve that checkpoint's own signing key. Where the
  governance chain still cannot be resolved that far — nothing canonical or proof-verified
  reaches a verified genesis — admission is refused (`GovernanceChainUnresolvable`) rather
  than falling back to a stale or partial snapshot.
- **Two verification states, enforced as a real boundary, not a label** (core spec §7.3).
  `ingest_checkpoint` records every signature-verified checkpoint as **authenticated**;
  `checkpoint::series_view` computes, fresh on every call from the store's current state,
  which of those are additionally **series-usable** — root recomputed against held entries,
  and RFC 9162 consistency verified against the nearest earlier series-usable member (and
  against a later one, once it exists, via *that* member's own check — the relationship is
  symmetric, so it is only ever computed once). Only series-usable checkpoints are eligible
  for range enumeration (`CheckpointNotSeriesUsable` otherwise), a `GET /v1/consistency`
  endpoint, or `ITUB`; an authenticated-but-not-series-usable checkpoint is retained and
  reported as such (`GET /v1/checkpoints` shows every authenticated member's state).
- **A gap-free-frontier computation that matches core spec §7.3's corrected rules.** The
  series has exactly one start, `cadence_epoch`; the genesis checkpoint (`tree_size ==
  genesis_entry_index + 1`) plays no anchoring role — it need not even be published. Instead,
  the earliest series-usable checkpoint committing the genesis manifest MUST carry a
  `checkpoint_time` within one cadence interval of `cadence_epoch`, using the genesis-governed
  cadence (since nothing precedes genesis); outside that window, the frontier is
  `FrontierStop::NoValidStart` regardless of that checkpoint's `tree_size`. Each subsequent
  interval is judged by the cadence of the manifest version governing its **earlier** member —
  the same "greatest entry index below the checkpoint's `tree_size`" rule used for keys, never
  a separate rule for cadence, and never applied retroactively across a later cadence change.
  `checkpoint_time` MUST be non-decreasing; a decrease is reported as a distinct
  `FrontierStop::DecreasingTime` violation, never folded into an ordinary gap. The series is
  ordered `(tree_size, checkpoint_time)` ascending, not `tree_size` alone (a quiet log
  republishes at unchanged `tree_size`); `checkpoint::series_view` also reports
  `root_divergences` — `tree_size` values where two authenticated members disagree on
  `root_hash`, detectable purely from checkpoint metadata, independent of which entries this
  mirror happens to hold. `ITUB` returns a value only for a series-usable member within the
  resulting frontier, and where a `tree_size` carries several series-usable members, the one
  with the **earliest** `checkpoint_time` governs.
- **Retrieval by entry id** (adaptor profile §10.1.1, unchanged in shape): present returns the
  stored bytes unaltered (raw `application/json`, or a `base64:` text form via
  `?encoding=base64`), absent is a 404 with an explicit note that absence is a fact about the
  interface, never evidence of non-existence.
- **Authenticated range enumeration** (adaptor profile §10.2-§10.5, unchanged in shape): the
  request shape of §10.3, the `AHLRP1` proof exactly as serialized in §10.5, and an offline
  `verify_range_response` that replays what a receiving verifier does — now gated on the
  named checkpoint being series-usable (see above).
- **Storage**: see above.

## Where the profile was ambiguous or under-specified

Reported as asked, for the next specification round — not papered over. Points closed by the
now-published core spec §7.3 are marked as such, most recently by commit `9962750` ("fix
series start, ties and comparison"), which closed items 4 and 5 below outright and corrected
this crate's own prior guess on item 4 in the process; the rest are new, surfaced by this
round's fixes.

1. **Resolved by core spec §7.3, no residual choice left**: the manifest `log` object's schema
   (field names, that `checkpoint_cadence`/`witness_grace_period` are ISO 8601 durations
   restricted to time components only, and `cadence_epoch` is RFC 3339) is now normative. Only
   `P[n]DT[n]H[n]M[n]S` is legal; a value carrying `Y`, or `M` in the date part, is malformed
   and `duration::parse_iso8601_duration_nanos` rejects it with a distinct
   [`MirrorError::ProhibitedDurationComponent`] rather than approximating a length for a
   calendar component that does not have a fixed one. (An earlier draft of this crate
   approximated `Y`/`M` at 365/30 days; the published spec text forecloses that reading, and
   this crate no longer does it.)
2. **Resolved by core spec §7.3**: "gap-free" is no longer just "a consistency proof from the
   predecessor is available" (which pairwise RFC 9162 consistency satisfies trivially and
   cannot, by construction, detect an omitted checkpoint). The cadence rule, the
   non-decreasing-time rule, and the explicit range-start condition in §7.3 are exactly what
   `checkpoint::compute_gap_free_frontier` implements.
3. **Resolved by core spec §7.3**: whether a checkpoint may be admitted before this mirror
   holds every entry it commits is now explicit — the authenticated/series-usable split. This
   crate's `ingest_checkpoint` implements it as specified.
4. **Resolved by core spec §7.3 — and this crate's own earlier guess on this point was
   superseded, not merely underspecified.** An earlier draft of this crate read a checkpoint's
   *genesis state* as `tree_size = genesis_entry_index + 1` (its own term for what §7.3 later
   named the *genesis checkpoint*) and treated that `tree_size` as an alternative, tree-size-
   based way for a series to start, alongside starting within cadence of `cadence_epoch`. §7.3
   now states this plainly: "the genesis checkpoint … need not be published, and is not a
   start point." The series has exactly one start — `cadence_epoch` — constrained instead by a
   corpus-validity window: the earliest checkpoint committing the genesis manifest MUST carry
   a `checkpoint_time` in `[cadence_epoch, cadence_epoch + checkpoint_cadence]` of the genesis
   version. `checkpoint::compute_gap_free_frontier` implements this window check and no longer
   treats `genesis_entry_index + 1` as a start condition in its own right; the corresponding
   test that exercised the old alternative-start reading was corrected to assert the new,
   single-start behavior (`a_checkpoint_at_the_genesis_checkpoint_size_outside_the_epoch_window_does_not_start_the_series`)
   rather than removed, so the now-wrong case stays covered.
5. **Resolved by core spec §7.3**: which manifest version's cadence governs the interval
   between `cadence_epoch` and the first published checkpoint is now stated directly — "judged
   under the genesis manifest version's cadence, since no earlier version exists to govern it"
   — matching what this crate had inferred (and flagged as an inference) before the text
   confirmed it.
6. **§10.1.1's "MAY additionally carry the entry index and an inclusion proof"** is optional
   ("MAY") and this crate does not implement it on the plain retrieval path — only the range
   endpoint returns proofs. A caller wanting an inclusion proof for a single entry can request
   a width-1 range (`from_index = i, to_index = i + 1`), which the profile itself notes "is
   an inclusion proof in another serialization" (§10.4). A deliberate scope choice, not an
   oversight.
7. **Consistency-proof serialization for the standalone `GET /v1/consistency` endpoint** is
   this crate's own invention — the profile fixes `AHLRP1` for range proofs (§10.5) and the
   receipt format's `consistency_path` shape (§8.3: a JSON array of `sha256:<hex>` strings)
   but does not define a request/response envelope for fetching a bare consistency proof
   outside a receipt. This crate uses the §8.3 array form for the path and a small ad hoc
   JSON wrapper around it; not profile-normative, and named as such.
8. **This crate does not validate a manifest's own producer-key rotation authority beyond
   signature and `predecessor` linkage** — e.g. it does not separately check that a
   *retiring* `key` statement's target key was itself ever validly added, since a key that
   was never added cannot resolve a signature in the first place, making the check redundant
   in practice but not stated as guaranteed by the specification text. Noted for completeness.

## Quick start

```bash
cargo build --release
```

Configuration is a JSON file matching `ConfigSpec` — the out-of-band genesis anchor core spec
§2.3.5 requires; everything else (checkpoint-signing keys, cadence, `cadence_epoch`) is read
from the verified genesis manifest itself, not configured here:

```json
{
  "log_id": "sha256:<hex Origin ID>",
  "genesis_manifest_entry_id": "sha256:<hex entry id of the trusted genesis manifest>",
  "genesis_producer_keys": [
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
| `POST` | `/v1/entries/stage` | stage one entry (§4.2 format checks; JSON body, envelope carried base64) |
| `POST` | `/v1/entries/promote` | promote a staged entry to canonical storage, given a Merkle inclusion proof against an already-authenticated checkpoint |
| `GET` | `/v1/entries/{entry_id}` | retrieval by entry id (§10.1.1); `?encoding=base64` for the text form |
| `POST` | `/v1/range` | authenticated range enumeration (§10.2-§10.5) against a series-usable checkpoint |
| `POST` | `/v1/checkpoints` | admit a checkpoint as authenticated (core spec §7.3), optionally with `entries_to_promote` to admit its entries — and any governance material they carry — in the same call |
| `GET` | `/v1/checkpoints` | every authenticated checkpoint, each labelled with its state |
| `GET` | `/v1/checkpoints/{tree_size}` | the most recently declared checkpoint at that size, with its state |
| `GET` | `/v1/itub/{index}` | `ITUB(index)`, gap-free-frontier-aware (core spec §7.3; adaptor profile §5.2.1) |
| `GET` | `/v1/consistency?from=&to=` | a consistency proof between two series-usable members |
| `GET` | `/health` | liveness |

None of this wire shape is normative except where it carries profile-defined material
(`range_proof.adaptor_form`, the checkpoint object, the inclusion/consistency path arrays) —
the request/response envelopes around them are this crate's own, chosen for a small, obvious
REST surface.

## Quality gates

MSRV 1.92, edition 2021. `cargo build --all-targets`, `cargo test`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, and
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` all pass with zero warnings.
`cargo llvm-cov --all-features --ignore-filename-regex 'src/bin/' --fail-under-lines 90`
passes at **95.84% line coverage** (95.03% region, 89.33% function); `src/bin/` is excluded as
thin process wiring (config load, socket bind, graceful shutdown) exercised by hand rather
than by unit tests, matching `ahl-core`'s convention for its own `src/bin/`. `cargo audit`
reports zero advisories against the full dependency tree. No `unwrap`/`expect`/`panic` in
library code paths (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]`
in `lib.rs` and the binary; test code is exempted via `#![cfg_attr(test, allow(...))]`, since
tests are not library code paths). No `unsafe` (`#![forbid(unsafe_code)]`).

Tests are deterministic: no wall-clock reads, no randomness. Checkpoint times, Ed25519 test
keys, and entry contents are all fixed values. Negative-path coverage specifically includes,
among many others: a manifest-typed entry with an invalid producer signature (not governance);
a manifest whose `predecessor` does not link to the active version (rejected, chain
unchanged); a checkpoint whose governing manifest is not yet resolvable (refused, never
resolved from an older snapshot); two individually-signed but mutually inconsistent
checkpoints (never both series-usable); a decreasing `checkpoint_time` (reported as a
violation, not a zero-length gap); and a cadence relaxation that does not retroactively
validate an earlier, already-violated interval.

## License

Apache-2.0. See `LICENSE`.

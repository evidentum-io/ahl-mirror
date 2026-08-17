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
retrievable/enumerable only once it carries a Merkle inclusion proof against a checkpoint this
mirror has itself authenticated — never on the strength of a submitted claim alone.
Checkpoint-signing keys are resolved the way the profile resolves them — from the manifest
entries this mirror already holds canonically, not from mutable configuration alone — honouring
per-key activation bounds. And the checkpoint series tracks whether it is *provably* gap-free at
a declared cadence, reporting `ITUB` as unavailable rather than guessing wherever it is not. See
"What is implemented" below for the detail.

## What this crate is not

It does not walk the statement graph (inputs, outputs, triggers, closure), does not verify
producer signatures, and does not validate manifest-chain linkage (`predecessor` pointers,
signature-based chain-of-trust) — those are a verifier's job (core spec §6). The one narrow
exception is the `manifest` module: it reads the `type` and `log` fields of `manifest`-typed
*canonical* entries, for the sole purpose of resolving checkpoint-signing keys and cadence the
way adaptor profile §7.3 requires — trusting a manifest entry's content purely because of
*where* it sits (core spec §2.3.5), not because its own signature or lineage was checked.

## Architecture

A library (`src/lib.rs` and siblings) plus a thin binary (`src/bin/ahl-mirror.rs`):

| module | responsibility |
| --- | --- |
| `metadata` | the fixed ATL adaptor metadata object (§4.2) and the log-tree leaf hash |
| `store` | durable storage — staged and canonical entries, the checkpoint series |
| `ingest` | the format checks a submitted entry must pass to be staged, and proof-gated promotion to canonical storage |
| `manifest` | resolving checkpoint-signing keys and cadence from canonical `manifest` entries, bootstrapped from a configured genesis anchor |
| `retrieval` | retrieval by entry id (§10.1.1), with a defensive re-hash before serving |
| `range` | range-proof generation, `AHLRP1` serialization, and offline verification |
| `checkpoint` | checkpoint parsing/signing, `ITUB`, series admission and consistency |
| `config` | the log this mirror serves and the genesis governance anchor it bootstraps from |
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
does not expose them: RFC 9162 consistency proofs, RFC 6962 inclusion-proof generation, and the
ATL-specific log-leaf construction of adaptor profile §4.2
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
  a row lands here only via a verified Merkle inclusion proof (see "Admission" below).
- `checkpoints(tree_size PRIMARY KEY, log_id, root_hash, checkpoint_time, key_id, signature)`
  — the canonical checkpoint series; the primary key doubles as the ordering `ITUB` needs.

`SQLite` was chosen over a plain content-addressed directory because the mirror needs three
things a directory does not give for free: an atomic, crash-safe link between "this index" and
"these exact bytes" so promotion can never leave a torn write behind; an efficient "smallest
`tree_size` strictly greater than `i`" query for `ITUB` (adaptor profile §5.2.1); and an
efficient contiguous-range scan for enumeration (§10.3). One file, one dependency, no server —
which is what the brief's "simple durable local store" asks for.

Concurrency: all access is serialized behind one connection and one mutex, and multi-step
admission (resolve a governance key, verify a signature, promote several entries, insert a
checkpoint) is a sequence of individually-safe calls rather than one database transaction —
every query still runs inside `tokio::task::spawn_blocking` so a slow database call never
stalls the async runtime. Each step re-checks its own preconditions at call time, so a
concurrent request interleaved between steps can only ever cause a later step to fail closed
(a fresh conflict or an incomplete-range error), never to admit something unverified. A mirror
is single-writer by construction (one producer, one log, per adaptor profile §3), so this is a
documented simplification, not a silent gap — a deployment with many concurrent writers would
want real transactions here first.

## What is implemented

- **Ingest, split into staging and evidence-gated promotion** (task item 1; the fix for
  admission without evidence of anchoring). `ingest::stage_entry` runs the format checks —
  bytes hash to the claimed entry id; parse as JSON; envelope-shaped (`payload` object,
  non-empty `signatures` array); JCS-canonical round-trip; ATL metadata equals the fixed
  adaptor object — and stores the result in `staged_entries`, which carries **no** claim about
  position or anchoring. `ingest::promote_entry` is the only path into canonical storage: it
  requires a Merkle inclusion proof of the staged bytes' log leaf against a checkpoint this
  mirror has already signature-verified, either via a prior `POST /v1/checkpoints` (standalone
  `POST /v1/entries/promote`) or supplied alongside a new checkpoint in the same call
  (`entries_to_promote`). A party with no authority over the log can stage anything; nothing
  they stage can ever produce a valid proof against a genuine root, so it never displaces the
  entry the log actually anchored at that index.
- **Checkpoint-key resolution via the manifest chain, not mutable configuration alone** (task
  item 2). `manifest::resolve` reads the `manifest`-typed entries this mirror holds
  *canonically* — never staged, unverified bytes — and uses the one with the greatest entry
  index below a checkpoint's `tree_size`, honouring each key's `valid_from_index` activation
  bound; a key a later manifest version drops is implicitly retired, since only the *current*
  version's key set is consulted. Genesis (index-0) trust is a locally configured anchor
  (`Config::keys`, `Config::genesis_manifest_entry_id`) — the receipt format's local-policy
  rule for a trust anchor an offline party cannot self-authenticate (core spec §2.3.5) — and is
  superseded in full the moment a manifest rotation is anchored and promoted.
- **A checkpoint series that tracks whether it is provably gap-free, and an `ITUB` that says so
  honestly** (task item 3). The series accepts members in any `tree_size` order — so a gap can
  be backfilled — and checks a newly admitted member for RFC 9162 consistency against **both**
  existing neighbours (predecessor and successor) whenever the backing entries are available.
  `checkpoint::gap_free_frontier` computes, from the declared cadence (resolved the same way as
  signing keys, via `manifest::resolve`, falling back to `Config::genesis_checkpoint_cadence_seconds`),
  the `tree_size` up to which no adjacent pair of series members is further apart in
  `checkpoint_time` than the cadence allows. `checkpoint::itub` returns a value **only** within
  that proven-gap-free prefix — never a value derived from a series that merely happens to be
  pairwise-consistent, which pairwise consistency alone cannot rule out being incomplete.
- **Retrieval by entry id** (task item... unchanged from round 1; adaptor profile §10.1.1):
  present returns the stored bytes unaltered (raw `application/json`, or a `base64:` text form
  via `?encoding=base64`), absent is a 404 with an explicit note that absence is a fact about
  the interface, never evidence of non-existence. A defensive re-hash runs before any bytes
  leave the store.
- **Authenticated range enumeration** (adaptor profile §10.2-§10.5, unchanged from round 1): the
  request shape of §10.3, the `AHLRP1` proof exactly as serialized in §10.5, and an offline
  `verify_range_response` that replays what a receiving verifier does. `build_range_response`
  never serves a proof it has not itself verified first.
- **Storage**: see above.

## Where the profile was ambiguous or under-specified

Reported as asked, for the next specification round — not papered over. Items 1-2 from the
first round were resolved by the fixes above; the rest, and two new points the fixes surfaced,
follow.

1. **Where does a standalone mirror's checkpoint-key trust actually start?** Adaptor profile
   §7.3 resolves a checkpoint-signing key against "the manifest version active for the
   checkpoint's `tree_size`", which composes cleanly *given* a manifest chain — but says
   nothing about how a component with no independent view of producer signatures should
   bootstrap that chain in the first place. This crate follows the receipt format's own
   local-policy rule (core spec §2.3.5): the genesis key set and, optionally, the genesis
   manifest's entry id are configured directly, out-of-band, exactly as an offline verifier
   configures its trust anchor. Everything past genesis is then read from anchored, canonical
   `manifest` entries. What is *not* validated is the manifest chain's own internal integrity
   — producer signatures on manifest statements, `predecessor` linkage, or that a rotation was
   itself issued by a key valid under the *previous* version (see `manifest`'s module docs for
   the full reasoning). A mirror is not a verifier; a deployment wanting that stronger guarantee
   needs a verifier component in front of or beside it.
2. **The manifest object's `log` block has no literal JSON schema in the material available.**
   Core spec §7.2 describes it in prose only — unlike the statement types of §2.3.1-§2.3.6,
   which each get a JSON example. This crate reads `log.keys` (an array of the `{key_id,
   pubkey, valid_from_index}` objects the profile *does* give verbatim elsewhere) and
   `log.checkpoint_cadence_seconds` (a plain integer count of seconds, this crate's own choice
   over an ISO 8601 duration or another encoding). Both are reported, not assumed silently —
   see `manifest`'s module docs for the exact shape. The next profile revision should settle
   this the way it settled every other statement type: with an example.
3. **Whether checkpoint admission may (or must) precede full entry availability is not
   addressed by the profile at all**, and this crate had to decide it: a checkpoint enters the
   canonical series on the strength of its authenticated signature alone, independent of
   whether this mirror yet holds every entry it commits (checkpoints and entry bytes routinely
   arrive on different schedules — the profile's own §10.1 gap analysis treats them as
   separately-served concerns). Root-recomputation and both-neighbour consistency checks then
   run *opportunistically*, whenever the full range happens to be canonical, rather than
   gating admission — entry-level correctness is never weakened by this, since no entry is ever
   promoted without its own inclusion proof regardless of whether the checkpoint-level
   self-check ran. An alternative reading — a checkpoint may not enter the series until its
   full range is canonical — is equally defensible and worth the next revision settling
   explicitly, since it changes what "in the canonical series" is allowed to mean under load.
4. **"Gap-free" (adaptor profile §5.2.2 item 1) is defined as "a consistency proof from the
   predecessor is available", which pairwise RFC 9162 consistency can satisfy trivially for any
   two checkpoints truly drawn from the same append-only tree — it cannot, by construction,
   detect a *missing* checkpoint the declared cadence implies should exist between two that
   individually verify.** The profile does not name a mechanism for that; this crate uses
   `checkpoint_time` deltas against the declared cadence (see point 2) as the actual gap
   detector, and treats pairwise consistency as necessary but not sufficient. Reported because
   this is a real gap in what §5.2.2 as written can enforce, not just an implementation choice.
5. **§10.1.1's "MAY additionally carry the entry index and an inclusion proof"** is optional
   ("MAY") and this crate does not implement it on the plain retrieval path — only the range
   endpoint returns proofs. A caller wanting an inclusion proof for a single entry can request
   a width-1 range (`from_index = i, to_index = i + 1`), which the profile itself notes "is
   an inclusion proof in another serialization" (§10.4). Documented as a deliberate scope
   choice, not an oversight.
6. **Consistency-proof serialization for the standalone `GET /v1/consistency` endpoint** is
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
  "genesis_manifest_entry_id": "sha256:<hex, optional but recommended>",
  "genesis_checkpoint_cadence_seconds": 300,
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
| `POST` | `/v1/entries/promote` | promote a staged entry to canonical storage, given a Merkle inclusion proof against an already-admitted checkpoint |
| `GET` | `/v1/entries/{entry_id}` | retrieval by entry id (§10.1.1); `?encoding=base64` for the text form |
| `POST` | `/v1/range` | authenticated range enumeration (§10.2-§10.5) |
| `POST` | `/v1/checkpoints` | admit a checkpoint into the canonical series (§5.2.2), optionally with `entries_to_promote` to admit its entries in the same call |
| `GET` | `/v1/checkpoints` | the full canonical series |
| `GET` | `/v1/checkpoints/{tree_size}` | one series member |
| `GET` | `/v1/itub/{index}` | `ITUB(index)`, gap-free-aware (§5.2.1-§5.2.2) |
| `GET` | `/v1/consistency?from=&to=` | a consistency proof between two series members |
| `GET` | `/health` | liveness |

None of this wire shape is normative except where it carries profile-defined material
(`range_proof.adaptor_form`, the checkpoint object, the inclusion/consistency path arrays) — the
request/response envelopes around them are this crate's own, chosen for a small, obvious REST
surface.

## Quality gates

MSRV 1.92, edition 2021. `cargo build --all-targets`, `cargo test`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, and
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` all pass with zero warnings.
`cargo llvm-cov --all-features --ignore-filename-regex 'src/bin/' --fail-under-lines 90`
passes at **96.42% line coverage** (95.35% region, 92.31% function); `src/bin/` is excluded as
thin process wiring (config load, socket bind, graceful shutdown) exercised by hand rather than
by unit tests, matching `ahl-core`'s convention for its own `src/bin/`. `cargo audit` reports
zero advisories against the full dependency tree. No `unwrap`/`expect`/`panic` in library code
paths (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]` in `lib.rs`
and the binary; test code is exempted via `#![cfg_attr(test, allow(...))]`, since tests are
not library code paths). No `unsafe` (`#![forbid(unsafe_code)]`).

Tests are deterministic: no wall-clock reads, no randomness. Checkpoint times, Ed25519 test
keys, and entry contents are all fixed values. Negative-path coverage specifically includes:
bytes that do not hash to their claimed entry id; a non-canonical envelope; wrong adaptor
metadata; an entry staged but never promoted (never retrievable); a checkpoint that cannot
promote bytes it does not genuinely commit; a range proof that fails to verify; a checkpoint
signed by a key outside its configured or manifest-declared validity window; and an `ITUB`
query against a series with an undetected time-cadence gap.

## License

Apache-2.0. See `LICENSE`.

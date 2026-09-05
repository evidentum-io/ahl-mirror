# ahl-mirror

An independent mirror for the [AHL Protocol](https://atl-protocol.org)'s `ahl-adaptor-atl-v1`
profile: byte-exact retrieval by entry id, authenticated range enumeration, and the canonical
checkpoint series a corpus needs to reach conformance level L3 on an ATL-backed log.

## No panic

`ahl-mirror` reaches no panicking construct on any input to the parsers it exposes — the
request bodies and query strings of its six routes (staging, promotion, range enumeration,
checkpoint ingest, retrieval and consistency), the checkpoint, `manifest` and `key` statements
it ingests and walks, the range-enumeration responses it verifies offline, and the deployment
configuration it reads at startup. Malformed, hostile or simply absurd input is reported as an
error and rendered as an HTTP status, never as an abort of the server process or of the task
serving the request. The mechanism is the package-level lints in `Cargo.toml`
(`clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`, `panic`,
`unreachable`, `todo`, `unimplemented`, `missing_panics_doc`, all denied and satisfied in
library and binary code rather than allowed at a site); the evidence is the nine libFuzzer
targets in [`fuzz/`](fuzz/README.md). The boundary: I/O, `SQLite` and network failures are
results rather than panics, and a store that cannot be opened or migrated is reported to the
operator instead of raised; allocation failure and stack exhaustion are out of scope, since
neither is a panic and neither is something a server can decline; nesting depth is bounded by
`serde_json`, which refuses a document nested deeper than 128 levels with an error rather than
recursing, so a `Value` obtained by parsing a request body is already bounded when this crate
sees it, while a `Value` built programmatically to arbitrary depth is not and is outside the
claim; no structure is ever sized by a number a request merely claims — a checkpoint's
`tree_size` is refused above the store's addressable `i64` index space and, below it, is
never allocated for, so the work a submission costs stays proportional to the entries
actually held rather than to the size it asserts; the size of a request body is bounded by
the deployment's own HTTP layer and not here;
and `ahl-core` and `atl-core` — which perform canonicalization, envelope verification, node
hashing and proof verification — are not covered, because the claim is about this crate's own
code. `ahl-core` states the same claim for itself.

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
| `store` | durable storage — staged and canonical entries with their log leaf hashes, the complete-subtree cache, the authenticated checkpoint set, and rotation-anchoring checkpoints held apart from it |
| `ingest` | the format checks a submitted entry must pass to be staged, and proof-gated promotion to canonical storage |
| `manifest` | the verified governance chain walk: producer-signature and `predecessor` checks, checkpoint-signing key and cadence resolution |
| `retrieval` | retrieval by entry id (§10.1.1), with a defensive re-hash before serving |
| `range` | range-proof generation from stored tree material, `AHLRP1` serialization, and offline verification |
| `checkpoint` | checkpoint parsing/signing, the authenticated/series-usable state machine, gap-free-frontier computation, `ITUB` |
| `config` | the log this mirror serves and the genesis governance anchor it bootstraps from |
| `http` | an `axum` router — thin handlers over the modules above, nothing more |

`tests/rotation_proof_end_to_end.rs` is the one place this crate runs `ahl-witness` too, as a
dev-dependency: I-D §7.1's `rotation_proofs[]` element is assembled from both components — this
crate serves the checkpoint and its inclusion path, the witness serves the cosignature — so the
test that proves the two halves compose has to run both, and hands the joined element to
`ahl_core::receipt::verify_receipt_report` unedited. It does so twice, once per half of §7.1's
definition: a LOG-key rotation, where the anchor is a thing apart from the series and several
anchors are held to show the two components pick the same one, and a WITNESS-set rotation, where
one checkpoint is both the series member the receipt is anchored under and the rotation proof's
own checkpoint. Nothing in the shipped crate depends on the
witness, and the independence core spec §3.3 requires of one is a runtime property, not a build
one.

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
  last genuinely verified state — never a reason to abort resolution outright. The one
  statement that *does* abort it is one whose signature verifies but whose declared revision
  this build does not: a `manifest` or `key` statement MUST declare `ahl_version` equal to the
  revision in force (`ahl_core::AHL_VERSION`, currently `0.4`), and one declaring an earlier
  revision — or none at all — is refused by name (`UnsupportedStatementVersion`), because
  revision 0.4 verifies no material issued under an earlier revision (I-D §2.2, §7.1) and
  skipping it would silently leave the previous governance version in force. The check runs on
  every candidate whose envelope verifies, before `predecessor`, `action` or any other payload
  member is read, so an authentic earlier-revision statement cannot slip past it by also
  failing some later check.
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
- **Range enumeration that reads the window and not the log** (adaptor profile §10.3-§10.5).
  A range proof carries the subtree hashes covering everything outside the requested window,
  so a naive builder hashes the whole `[0, tree_size)` prefix to produce them. This one does
  not. Each entry's ATL log leaf hash (§4.2) is stored beside it at promotion, and the root of
  every **complete** power-of-two subtree is stored as it becomes complete (RFC 6962 geometry),
  so every proof node is one stored hash or an `O(log n)` fold over stored hashes, and entry
  BYTES are read for `[from_index, to_index)` and for nothing else. An existing store is
  migrated on open: the leaf-hash column is backfilled once and the subtree cache is rebuilt
  wherever it does not hold exactly the nodes a log of the stored size completes. The response
  bytes are unchanged — `range::build_range_response_from_prefix`, the previous full-prefix
  builder, is retained as a test oracle and
  `the_windowed_builder_agrees_with_a_full_prefix_build` holds the two together over every
  window of every tree shape up to 33 entries. Measured on a 10-entry window over a
  10 000-entry log: **778 890 bytes read before, 1 772 after** (780 entry bytes plus 31 stored
  32-octet tree nodes), and `build_range_response_measured` reports that figure rather than
  leaving it to be asserted.
- **Every root and every proof out of the same cache** (core spec §7.3; adaptor profile
  §5.2.2). The material above is not only for enumeration. The root check at checkpoint
  ingest, each series member's root and its consistency proof with the nearest earlier
  series-usable member (what `ITUB` and `GET /v1/checkpoints` rest on), and the
  `GET /v1/consistency` endpoint all open their roots and paths through the stored leaf
  hashes and the complete-subtree cache: `O(log n)` stored 32-octet nodes, and not one entry
  envelope. Measured on a proof between sizes 5 000 and 10 000 over a 10 000-entry log:
  **778 890 bytes read before, 480 after** (15 stored nodes). The proofs are unchanged —
  `store::consistency_proof_from_entry_bytes`, the previous entry-bytes build, is retained as
  a test oracle, and `the_cached_prover_agrees_with_an_entry_bytes_build` holds the two
  together node for node for every `(m, n)` pair over every tree shape up to 33 entries
  (`checkpoint::tests::the_stored_series_checks_agree_with_the_leaf_sequence_forms` does the
  same for the series checks, against the public `verify_series_consistency`). What still
  reads the entry prefix is governance resolution, which must parse the `manifest` and `key`
  statements to know which keys govern at all — bytes read to be parsed, never to rebuild a
  root.
- **A cache gap is refused, not silently recomputed.** `atl-core`'s node callback reads an
  absent node as "descend and recompute", which would turn a missing `subtree_roots` row into
  an `O(n)` fold over leaf hashes — the logarithmic promise quietly broken, on derived material
  the deployment has just discovered it cannot vouch for. So a node that is *complete* under
  the tree being opened, and absent, raises `TreeMaterialMissing` naming the node: the
  consistency endpoint and `ITUB` return 500 rather than an answer, range enumeration and
  checkpoint admission refuse, and the checkpoint series propagates the fault instead of
  downgrading its members to "merely authenticated". Admission additionally checks the block
  roots of the prefix up front (`O(log n)` lookups), so a hole is usually caught before any
  proof is attempted. The remedy is the cache rebuild the store already runs **on open**, and
  it stays there: a serving path checks, it never repairs.
- **Rotation-anchoring checkpoints, held under the outgoing state and served apart**
  (I-D §7.1's transition exception; adaptor profile §16 item 10). Every submitted checkpoint is
  asked two independent questions. The ordinary one: does it verify under the manifest version
  active for its own `tree_size`? And the exception: is it rotation-anchoring material for any
  **governance-key rotation** the entry prefix contains — a version whose log key objects or
  whose witness key objects differ from its predecessor's — with `tree_size` GREATER than that
  version's entry index and a signature verifying under a log key of the PREDECESSOR version's
  set? The search is over every such rotation, not merely the active version, because §7.1 says
  the version active for a rotation proof's checkpoint "is the rotating manifest OR A LATER
  ONE": a checkpoint several rotations past the one it anchors is matched against that
  rotation's own predecessor. A submission MAY name the rotation it is offered for
  (`rotation_for`). It narrows nothing: every rotation the checkpoint qualifies for is
  discovered and recorded either way — one checkpoint under an unchanged log key can anchor
  several witness-set rotations at once, which is why `rotation_anchors` is a list — because
  what a checkpoint anchors is a fact about the log, not about what the submitter knew. What
  naming changes is the report: a name absent from the discovered set is refused with the reason.

  A checkpoint can earn BOTH answers, and the case is not exotic: §7.1 makes a change to the
  witness key objects a rotation on its own, and such a rotation leaves the log key set alone,
  so the ordinary checkpoints of the series are themselves what a `rotation_proofs[]` element
  needs. `POST /v1/checkpoints` therefore reports two facts, `series_member` and
  `rotation_anchors[]`, rather than one choice. The two records point at one checkpoint, held in
  two tables: the series routes read `checkpoints`, the rotation route reads
  `rotation_checkpoints`, and neither shadows the other. Nothing else is ever accepted under a
  retired key, and a checkpoint that answers neither question is refused with the failure it
  earned under the ordinary rule.

  Rotation material is never returned as a series member (`GET /v1/checkpoints`,
  `/v1/checkpoints/{size}`, `ITUB`, consistency neighbours). It is served only from
  `GET /v1/rotation-proofs/{manifest_entry_index}`, in the `governance.rotation_proofs[]`
  element shape §7.1 defines — `{manifest_entry_index, checkpoint, inclusion_path, witnesses}`.
  `witnesses` is always empty: a mirror does not cosign, so a deployment claiming L3 fills that
  member from its witness before the element goes into a receipt. Where several checkpoints
  qualify for one rotation, the route serves the smallest `(tree_size, checkpoint_time)`, and
  the store keeps only anchors that could be served, so which one is served does not depend on
  the order submissions arrived in. Held apart is not held outside the rules: a
  rotation-anchoring checkpoint that contradicts a series member at the same `tree_size` is
  equivocation and is reported through the same path as any other divergence (core spec §7.3),
  which the rotation route then refuses to serve past.
- **Two verification states, enforced as a real boundary, not a label** (core spec §7.3).
  `ingest_checkpoint` records every signature-verified checkpoint as **authenticated**;
  `checkpoint::series_view` computes, fresh on every call from the store's current state,
  which of those are additionally **series-usable** — root recomputed against held entries,
  and RFC 9162 consistency verified against the nearest earlier series-usable member (and
  against a later one, once it exists, via *that* member's own check — the relationship is
  symmetric, so it is only ever computed once). Only series-usable checkpoints strictly below
  the equivocation floor (see below), if the series has one, are eligible for range
  enumeration (`CheckpointNotSeriesUsable`, or `SeriesEquivocated` at or beyond the floor,
  otherwise), a `GET /v1/consistency` endpoint, `GET /v1/checkpoints/{tree_size}`, or `ITUB`;
  an authenticated-but-not-series-usable checkpoint is retained and reported as such
  (`GET /v1/checkpoints`, with no `tree_size`, shows every authenticated member's state and
  never refuses — nothing is hidden there even at or beyond the floor).
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
- **Equivocation is a hard boundary, not a mere finding (core spec §7.3: "Equivocation ends
  the series").** Two authenticated members sharing a `tree_size` with differing `root_hash`
  values are equivocation, not a tie; `SeriesView::equivocation_floor` is the lowest such
  `tree_size`, if any. From it onward the series is no longer canonical: `gap_free_frontier`
  never reaches or passes it (`FrontierStop::Equivocation`, permanently — no later arrival of
  entries or checkpoints can un-equivocate a log that already published two conflicting
  roots), so `ITUB` refuses there automatically. Range enumeration, the consistency endpoint,
  and the single-checkpoint lookup independently refuse the same region
  (`MirrorError::SeriesEquivocated`, HTTP 409) even for a `tree_size` whose own root happens
  to recompute correctly against entries this mirror holds — a checkpoint agreeing with this
  mirror's local copy does not un-equivocate a log that published a conflicting root
  elsewhere. Members strictly below the floor are unaffected.
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
now-published core spec §7.3 are marked as such: commit `9962750` ("fix series start, ties
and comparison") closed items 4 and 5 below outright and corrected this crate's own prior
guess on item 4 in the process; commit `82b96c0` ("equivocation boundary and fraction rule")
closed item 9's open question about the root-divergence check's scope, confirming this
crate's own choice.

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
9. **Resolved by core spec §7.3 (commit `82b96c0`), confirming this crate's own choice.**
   Previously flagged: whether the corpus-validity window check and the root-divergence
   finding are scoped to series-usable checkpoints only or to every authenticated one, since
   §7.3 said "the earliest checkpoint committing the genesis manifest" for the window and
   "members" for the root-tie rule without saying which. The equivocation paragraph now
   states the root-tie rule over "two *authenticated* members" explicitly, matching this
   crate's wider scope for `SeriesView::root_divergences` (and now `equivocation_floor`) —
   computed from every authenticated checkpoint, detectable from metadata alone before either
   member is proven series-usable or entries even exist to check them against. The window
   check remains correctly scoped to series-usable members only (`compute_gap_free_frontier`
   still takes `usable: &[Checkpoint]`): an unverified checkpoint's claimed `checkpoint_time`
   must not gate whether a range is judged to start at all.
10. **Equivocation is now a hard boundary (core spec §7.3, commit `82b96c0`).** Two
    authenticated members sharing a `tree_size` with differing `root_hash` are equivocation:
    "no incorporation bound, enumeration response or completeness claim may be grounded at or
    beyond that point ... a party serving series-dependent material MUST report the
    divergence rather than choosing a branch." `SeriesView::equivocation_floor` and
    `FrontierStop::Equivocation` implement the boundary in `itub` (via `gap_free_frontier`,
    which never reaches or passes the floor), range enumeration and the consistency endpoint
    (both via `series_usable_checkpoint`, which refuses `tree_size >= floor` before ever
    inspecting which specific checkpoint sits there), and additionally the single-checkpoint
    lookup (`GET /v1/checkpoints/{tree_size}`), whose `max_by(checkpoint_time)` tie-break was
    exactly the "pick a branch" pattern the rule prohibits — extended beyond the three paths
    named for this fix since it exhibited the identical defect. `GET /v1/checkpoints` (no
    `tree_size`) is deliberately left unguarded: it already reports every authenticated
    member with its own state, divergence included, hiding nothing. One implementer's choice
    remains: when the `usable` list is exhausted before ever reaching the equivocation floor
    (e.g. floor is far beyond any currently-published checkpoint), this crate still reports
    `FrontierStop::Equivocation` rather than `None`, on the reasoning that a known, permanent
    equivocation is more informative than reporting a "clean, just needs more data" stop that
    a caller might reasonably retry expecting to eventually succeed. §7.3 does not state
    which stop reason should be reported in that specific case.

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
| `GET` | `/v1/rotation-proofs/{manifest_entry_index}` | the `governance.rotation_proofs[]` element for the governance-key rotation anchored at that entry index (I-D §7.1); `404` where none is held |
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

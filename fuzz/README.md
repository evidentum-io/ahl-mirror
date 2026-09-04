# ahl-mirror fuzz targets

Nine libFuzzer targets, one per place the mirror reads bytes it did not write. Six sit behind
`http::seam`, which runs exactly what the matching handler runs — the same private request
type, the same field decoding, the same library call — without `axum`'s routing or the
`spawn_blocking` hop, neither of which parses anything. The other three take documents that
reach the crate by other routes.

| Target | Input | Reaches |
| --- | --- | --- |
| `stage` | `POST /v1/entries/stage` body | entry-id recomputation, envelope shape, JCS round-trip, adaptor metadata comparison |
| `promote` | `POST /v1/entries/promote` body | `sha256:<hex>` proof path decoding and RFC 6962 inclusion verification at a client-chosen index |
| `checkpoint` | `POST /v1/checkpoints` body | checkpoint field parsing, the optional 98-byte raw blob, governance resolution, root recomputation, signature check, batch promotion, and the rotation search behind the optional `rotation_for` (I-D §7.1) |
| `range` | `POST /v1/range` body | series-usable checkpoint lookup, then range slicing and `AHLRP1` generation and re-verification over client-chosen bounds |
| `range_response` | a range response document | the offline verifier a client runs against a foreign mirror: proof decoding, per-entry leaf recomputation, root check |
| `query` | path segment and query string | `axum`'s `Query` over the module's own query types, retrieval by id, the consistency endpoint's two bounds, `ITUB`, and the rotation-proof route's `manifest_entry_index` — which reaches the store's tree geometry, so the whole element build runs |
| `governance` | one anchored statement | the manifest chain walk, as genesis and as a successor: producer keys, the `log` block, cadence, epoch, `predecessor` |
| `config` | the deployment configuration | key decoding and `key_id` recomputation at startup |
| `text` | one duration or checkpoint time | the ISO 8601 duration grammar and the §6.3 time rendering, where this crate's untrusted arithmetic lives |

`query` splits its input on the first NUL byte: left half path segment, right half query string.

No target unwraps, indexes or asserts, and the fuzz crate denies `unwrap_used`, `expect_used`,
`indexing_slicing`, `arithmetic_side_effects` and `panic` for itself — a panic raised by the
harness would be reported as a finding against the library under test.

The fixture is built, not read: this crate ships no `test_data/`, because its corpus is a live
`SQLite` store. `src/lib.rs` derives everything from two fixed key seeds and one fixed genesis
manifest, so a run does no file I/O and repeats exactly. The targets that write get a fresh
in-memory store per input, so a crash reproduces from that input alone; the read-only targets
share one store opened once.

## Running

```sh
cargo +nightly fuzz build
mkdir -p fuzz/corpus/stage fuzz/corpus/promote fuzz/corpus/checkpoint fuzz/corpus/range \
         fuzz/corpus/range_response fuzz/corpus/query fuzz/corpus/governance \
         fuzz/corpus/config fuzz/corpus/text
cargo +nightly fuzz run stage fuzz/corpus/stage fuzz/seeds/stage -- -max_total_time=60
```

The `mkdir` is not optional: libFuzzer requires the corpus directory to exist. Substitute any
other target name in the last line; `fuzz/seeds/<target>` is passed as a second, read-only
corpus directory so the committed seeds are never rewritten.

The seeds under `seeds/` are the same fixture material, one file per shape worth starting
from: for each target, the documents a correct client sends alongside the rejections that are
interesting to mutate — a wrong entry id, a non-canonical envelope, an inverted range, a
proof path of nonsense hex, a duration that overflows its nanosecond accumulator.
`corpus/` and `artifacts/` are working directories and are not committed.

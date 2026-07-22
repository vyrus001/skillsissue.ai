# Tracee telemetry viewer

`skill-telemetry-view` is a local, read-only visualizer for one skillsissue.ai
detonation run. It follows the repository's Rust tooling, reads Tracee JSONL
without a JavaScript build step, and serves a dependency-free Canvas UI only on
a loopback address.

## Run it

Pass a run directory (recommended), its `run.json`, or an evidence file:

```bash
./telemetry-viewer.sh \
  telemetry/2026/07/14/run_961e7f0d8181beac92ddb9fc

./telemetry-viewer.sh path/to/events.partial.jsonl.zst \
  --port 0
```

The command prints the selected `http://127.0.0.1:<port>` URL. Port `0` asks the
OS for an available port. The server rejects non-loopback bind addresses because
all telemetry strings and raw JSON are attacker-controlled evidence.

To validate and summarize a run without starting the UI:

```bash
./telemetry-viewer.sh inspect telemetry/YYYY/MM/DD/<run-id>
```

Both completed `events.jsonl.zst` and partial `events.partial.jsonl.zst` captures
are supported, as are their uncompressed JSONL forms. When a directory is
selected, the viewer reads metadata from `run.json` and resolves only the
basename of its declared `telemetry_path` inside that directory.

## What the graph means

- Process-image nodes come from `sched_process_exec`/exec events. An outlined
  “observed” anchor is used when activity exists before an exec or when no exec
  event was captured; it is labeled as observed rather than invented.
- Recorded forks connect the parent's active image to the child's first observed
  image. `processEntityId` is preferred over PID so PID reuse does not merge
  unrelated processes; namespace PPID is only a fallback.
- File activity distinguishes reads, writes, read/write opens, create/truncate
  opens, rename, delete, permission changes, and other captured lifecycle events.
  Tracee read/write syscalls usually contain only an FD, so the viewer replays
  successful open/dup/close/pipe operations and recorded fork inheritance. An
  unresolved FD stays explicitly unresolved.
- Socket activity uses `SockAddr.sa_family` and socket type together: Unix
  families are Unix sockets, and Internet `SOCK_STREAM`/`SOCK_DGRAM` events are
  TCP/UDP. Connect is outbound; bind/listen is inbound-open; accept is
  inbound-accept. Missing family/type and unlabeled numeric packet direction are
  reported as unknown rather than guessed.
- The x coordinate is the Tracee nanosecond timestamp on one shared axis. IDs and
  timestamps are serialized as decimal strings to avoid JavaScript integer
  precision loss. Source sequence provides deterministic order for equal or
  missing timestamps. Process relationships descend along the y axis.

The current detonation policy records connect/security-connect and DNS but does
not record bind, listen, or accept. A run produced by that policy can therefore
show outbound and ambiguous activity, but absence of an inbound node is not
proof that no listener existed. If a different Tracee policy captures inbound
events, the normalizer classifies them.

## Dense traces and raw evidence

The default UI groups matching activity within 10 ms by operation, process
image, target, transport, and direction. Controls can change the bucket, group
only by operation, or render one node per event. Category, transport, direction,
and text filters affect the view without deleting data. Aggregates retain every
underlying event ID; node inspection and the **All events** browser retrieve the
full normalized record and original Tracee JSON through paged local endpoints.

Loading fails instead of silently truncating when a limit is exceeded. Defaults:

- 1,000,000 parsed events;
- 256 MiB decompressed JSONL;
- 4 MiB per JSONL line; and
- 500 records per browser API page.

Raise input limits explicitly when inspecting a trusted larger capture, for
example `--max-events 2000000 --max-uncompressed-bytes 536870912`. Compression,
event, request, page, and bind-address limits are performance and exposure
safeguards; they do not alter a successfully loaded graph.

## Tests

```bash
cargo test -p skill-telemetry-view
cargo clippy -p skill-telemetry-view --all-targets -- -D warnings
```

Focused tests cover Tracee argument normalization, compressed input, stable
timestamp ordering, process/fork relationships, FD-backed file attribution,
file operation labels, TCP/UDP/Unix and direction classification, aggregation
coverage, and deterministic layout inputs.

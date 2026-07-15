# Detonation telemetry

Every attempted detonation gets an immutable directory:

```text
telemetry/YYYY/MM/DD/<run-id>/
  run.json
  tracee-policy.yaml
  target-container-id
  events.jsonl.zst          # completed capture, possibly marked unusable
  events.partial.jsonl.zst  # failed attempt with attributable events
  agent.stdout.zst          # when the target started
  agent.stderr.zst          # when the target started
  collector-stats.json      # when collector finalization ran
  collector.log.zst         # when the collector emitted output
  failure.txt               # failed attempts only
```

The exact file set depends on the attempt outcome and is declared in
`run.json`. The publisher verifies allowed filenames, byte caps, SHA-256,
run/status linkage, collector health, and the target exec sentinel before it
updates `data/runs.csv`. `events*.jsonl.zst` is the bounded raw Tracee eBPF
stream; `data/assessments.csv` and `data/findings.csv` contain replayable
analyzer output.

Do not place credentials here. The sandbox receives synthetic `#data_*`
markers only, and output is capped before it is committed. All strings and
compressed bytes in this tree remain attacker-controlled evidence.

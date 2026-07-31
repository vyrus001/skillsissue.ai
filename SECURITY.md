# Security model

This repository processes adversarial content. A passing verdict is evidence
about one bounded execution, not proof that a skill is safe.

## Trust boundaries

Acquired skills, archives, Git repositories, SkillJect fixtures, target output,
Tracee event fields, URLs, and CSV strings are untrusted. Ingestion never
executes them. Analysis parses stored telemetry without running target output.

The Rust detonation supervisor and the digest-pinned Tracee collector are
trusted infrastructure. For hosted workflows, GitHub's runner control plane,
VM image, and VM isolation are also trusted infrastructure. The supervisor
receives the Docker socket so it can create the target and sensor. The sensor
is intentionally host-privileged and uses
host PID and cgroup namespaces, and mounts `/var/run` read-only for container
runtime metadata; a read-only socket can still be contacted. It therefore has
`--network none`, no repository or Actions token, and must run only on a fresh
host that is destroyed after the job. Container flags do not turn this sensor
into a security boundary.

The untrusted target is a distinct non-root container. It receives no Docker or
host-control socket, repository, `.git`, host secrets, or write token. Its root is read-only; all
capabilities and direct public egress are removed; no-new-privileges, PID, CPU,
memory, output, event, and wall-clock limits are enforced. The validated skill
seed is read-only, while mutable skill state and `/tmp` live on byte/inode-capped
tmpfs mounts; Docker's own target and collector logs are capped as well. The
target joins a fresh Docker-internal network with no external gateway. Its only
network peer is a non-root dual-homed interception proxy. The target receives
the public half of a per-run CA; the CA private key exists only in the proxy's
ephemeral configuration directory. The proxy accepts only HTTP(S) `GET`/`HEAD`
on ports 80/443, rejects private, loopback, link-local, metadata, single-label,
and mixed public/private DNS destinations, strips caller authentication and
cookies, and disallows bodies and protocol upgrades. It records each bounded
response body before delivery. Clients that bypass proxy settings, use an
unsupported protocol, or pin a remote certificate fail because the target has
no direct route.

For a CLI run, the target additionally receives only a dedicated read-only
Docker volume containing the Unix socket; its trusted PID 1 harness forwards
fixed loopback port 8787 to that socket with bounded concurrency. The credential
relay alone joins the fresh external egress network and is not attached to the
target network. The socket remains directly connectable by the target UID, so
the relay's strict request schema and cumulative budgets are the provider
control boundary. The sensor remains on `--network none`, and cleanup removes
the per-run internal and external networks, socket volume, target, sensor,
proxy, and optional relay.

Codex and Claude never reuse host login state, mount provider configuration, or
receive a real API key. The harness clears its inherited environment and gives
the CLI only a fixed dummy key and the loopback relay URL. The trusted
supervisor writes the selected provider key to a new mode-0400 per-run file and
bind-mounts it read-only into the relay only; neither the target nor the sensor
can read it. The relay strips caller authentication, injects the real key, and
permits only HTTPS requests to the hard-coded OpenAI Responses or Anthropic
Messages endpoints. It rejects provider-hosted web, MCP, connector, code,
computer, file, and image tools; accepts only the pinned CLIs' local tool
envelopes; disables proxies and redirects; and bounds per-request bytes,
cumulative bytes, output tokens, request count, concurrency, and time. It does
not persist authentication/routing headers, and recursively redacts
secret-shaped JSON fields before recording bounded request and response bodies.
Treat those transcripts as sensitive attacker-controlled evidence even after
redaction.

Intercepted public-download bodies are retained byte-for-byte as base64 with a
SHA-256 digest. They are attacker-controlled executable content, may contain
sensitive-looking data supplied by a remote host, and must never be rendered as
active HTML or executed during analysis. The static viewer shows only inert
text/hex previews and requires an explicit download action.

For behavioral coverage, Codex runs with its inner sandbox set to
`danger-full-access`, and Claude runs with `--dangerously-skip-permissions`.
Those modes grant only what the outer target container already possesses; the
actual boundary remains the non-root, capability-free, no-new-privileges,
read-only and resource-bounded container described above. Never use either
mode when the target has a host/ordinary bridge network, Docker socket, host
credentials, or broader mounts.

## CI and publication

- Treat repository administrators and anyone allowed to edit or dispatch
  workflows as control-plane principals. Protect `.github/workflows/`, the
  default branch, and publisher-bypass settings with required review and
  CODEOWNERS where available.
- Never detonate pull-request code. The capture and evaluation jobs use full
  `ubuntu-24.04` GitHub-hosted VMs, not the unprivileged `ubuntu-slim` runner.
  GitHub provisions a fresh VM and isolated Docker daemon for each matrix leg
  and destroys the VM after the job.
- Treat hosted eBPF support as a fail-closed runtime prerequisite, not a GitHub
  service guarantee. Preserve the checks for BTF, cgroup v2, the local Docker
  socket, an empty daemon, and `RUNNER_ENVIRONMENT=github-hosted`. If a runner
  image update breaks Tracee, stop detonation until the pinned OS label works
  again; do not bypass collector health or allow missing telemetry to produce a
  benign verdict.
- Before provider-backed detonation, create a GitHub environment named
  `hosted-detonation`. Restrict its deployment branches to the default branch,
  disable administrator bypass where available, and store `OPENAI_API_KEY` and
  `ANTHROPIC_API_KEY` only as environment secrets. Set the environment variable
  `HOSTED_DETONATION_ENABLED=true` after these controls are configured. A
  manual dispatch can target another Git ref, so the workflow's default-ref
  check is defense in depth; the environment deployment-branch policy is the
  external secret boundary.
- Run `evaluate-skillject.yml` with limit 1 before enabling the detonation
  schedule and after any hosted-runner kernel change. It is the secret-free
  end-to-end eBPF smoke test; inspect its uploaded evidence for collector health
  and the required target exec and harness-completion sentinels.
- Apart from a dedicated, low-privilege and spend-capped OpenAI or Anthropic key
  released from `hosted-detonation` only to the trusted supervisor for the
  per-run relay, do not attach cloud, package-registry, SSH, signing, provider,
  or repository write credentials to capture jobs. Do not configure OIDC or a
  cloud workload identity for these jobs. The workflow rejects common
  credential files and environment variables. Rotate the relay key after any
  abnormal runner termination.
- Keep default-branch checkouts explicit. The serialized planner resolves the
  current default-branch tip when it starts, and every shard in that matrix
  checks out that same immutable commit. Capture and acquisition jobs
  publish artifacts to separate clean jobs; only publisher jobs receive an
  Actions write token.
- Keep third-party actions, the Rust toolchain, base images, and Tracee pinned.
  Review and update pins deliberately.
- Preserve matrix `fail-fast: false`, separate per-shard artifact directories,
  aggregate telemetry validation, and the typed merge and artifact validators.
  They reject path escape, symlinks, unexpected files, duplicate logical run
  keys, stale captures for already completed runs, immutable-ID conflicts,
  formula-prefixed CSV fields, malformed telemetry linkage, size overruns, and
  candidate-platform promotion.
- Preserve `queue: max` on both the workflow-level detonation group and the
  shared publisher group. Serializing whole detonation workflows lets each
  queued planner observe the captures published by its predecessor before it
  assigns more work. Each publisher fetches the latest default branch into a
  fresh worktree and reruns all validation and typed reduction before each of
  at most three push attempts. Do not replace this with a blind rebase of
  generated CSVs. Configure branch protection to allow this narrow bot push
  path, or change publication to reviewed pull requests.
- Treat a publication-cap failure as a failed capture, not as permission to
  raise limits blindly. Repository history retains committed telemetry even
  after file deletion.

## Detection limitations

Dynamic analysis observes only reached behavior. An environment-gated, delayed,
model-dependent, or otherwise untriggered path is a false negative. Collector
loss, missing sentinel events, truncation, or failed cleanup prevents a benign
verdict. Newly inferred platforms remain disabled candidates until a human
verifies ownership, API behavior, legal terms, rate limits, and an adapter.

Report vulnerabilities privately through GitHub Security Advisories rather than
opening a public issue containing a working payload.

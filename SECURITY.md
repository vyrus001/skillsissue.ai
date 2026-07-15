# Security model

This repository processes adversarial content. A passing verdict is evidence
about one bounded execution, not proof that a skill is safe.

## Trust boundaries

Acquired skills, archives, Git repositories, SkillJect fixtures, target output,
Tracee event fields, URLs, and CSV strings are untrusted. Ingestion never
executes them. Analysis parses stored telemetry without running target output.

The Rust detonation supervisor and the digest-pinned Tracee collector are
trusted infrastructure. The supervisor receives the Docker socket so it can
create the target and sensor. The sensor is intentionally host-privileged, uses
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
target adapters use `--network none`. For a CLI run, the target receives only a
dedicated read-only Docker volume containing the Unix socket; its trusted PID 1 harness forwards
fixed loopback port 8787 to that socket with bounded concurrency. The credential
relay alone joins a fresh egress network, so the target has no bridge gateway or
direct route to the Internet. The socket remains directly connectable by the
target UID, so the relay's strict request schema and cumulative budgets are the
provider control boundary. The sensor remains on `--network none`, and cleanup removes
the per-run relay egress network, socket volume, and all three containers.

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
not log credentials or bodies.

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
- Never detonate pull-request code or use a persistent self-hosted runner.
- Map the `disposable` runner label to a freshly provisioned VM with cgroup v2,
  BTF, eBPF, Docker, and Actions Runner 2.329.0 or newer, then destroy it after
  every capture job. Every matrix leg needs its own VM and isolated Docker
  daemon; never register several shard runners on one shared host.
- Put those runners in a dedicated runner group restricted to the two exact
  default-branch workflow references, for example
  `<owner>/<repo>/.github/workflows/detonate.yml@refs/heads/main` and
  `<owner>/<repo>/.github/workflows/evaluate-skillject.yml@refs/heads/main`.
  A manual dispatch can target another Git ref, and GitHub evaluates the
  workflow definition at that ref. The in-workflow default-ref checks prevent
  mistakes; the externally configured runner-group restriction is the actual
  control against branch-modified workflow YAML.
- If your GitHub plan or repository ownership does not support selected-workflow
  runner groups, do not leave a self-hosted runner registered while privileged
  `workflow_dispatch` entry points are available. Move the repository to an
  organization with that control, remove manual dispatch, or provision a JIT
  runner only from an external trusted scheduler.
- Apart from a dedicated, low-privilege and spend-capped OpenAI or Anthropic key
  supplied only to the trusted supervisor for the per-run relay, do not attach
  cloud, package-registry, SSH, signing, provider, or repository write
  credentials to capture jobs, including ambient VM instance metadata or
  workload identity. The workflow rejects common credential files and
  environment variables, but runner provisioning must enforce the broader
  no-identity boundary. Rotate the relay key after any abnormal runner
  termination.
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

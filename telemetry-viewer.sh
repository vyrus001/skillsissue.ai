#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
manifest_path="${script_dir}/Cargo.toml"

usage() {
  cat <<'EOF'
Usage:
  ./telemetry-viewer.sh <run-directory|run.json|events.jsonl[.zst]> [viewer options]
  ./telemetry-viewer.sh inspect <run-directory|run.json|events.jsonl[.zst]> [limit options]

Examples:
  ./telemetry-viewer.sh telemetry/2026/07/14/run_961e7f0d8181beac92ddb9fc
  ./telemetry-viewer.sh telemetry/2026/07/14/run_961e7f0d8181beac92ddb9fc --port 0
  ./telemetry-viewer.sh inspect telemetry/2026/07/14/run_961e7f0d8181beac92ddb9fc

The viewer loads one selected run at a time and prints its loopback URL.
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

case "${1}" in
  -h|--help|help)
    usage
    exit 0
    ;;
  inspect)
    shift
    if [[ $# -eq 0 ]]; then
      usage >&2
      exit 2
    fi
    exec cargo run --quiet --manifest-path "${manifest_path}" \
      -p skill-telemetry-view -- inspect "$@"
    ;;
  *)
    exec cargo run --quiet --manifest-path "${manifest_path}" \
      -p skill-telemetry-view -- serve "$@"
    ;;
esac

#!/bin/sh
set -eu

environment_name="hosted-detonation"
adapter="codex-cli"
limit="1"
shard_count="1"
max_parallel="1"
repository=""
check_only="false"
assume_yes="false"
watch_run="true"

usage() {
  cat <<'EOF'
Usage: scripts/run-hosted-detonation.sh [options]

Validate the hosted-detonation environment and dispatch detonate.yml on the
repository's default branch. Defaults to one Codex skill on one runner.

Options:
  --adapter codex-cli|claude-cli  Agent harness (default: codex-cli)
  --limit 1|2                    Skills per shard (default: 1)
  --shards 1..16                 Deterministic shards (default: 1)
  --max-parallel 1..16           Concurrent runners (default: 1)
  --repo OWNER/REPO              Repository (default: current gh repository)
  --check                        Validate controls without dispatching
  --yes                          Skip the interactive cost confirmation
  --no-watch                     Return after dispatch instead of watching
  -h, --help                     Show this help
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

is_positive_integer() {
  case "$1" in
    ""|*[!0-9]*) return 1 ;;
    *) test "$1" -ge 1 ;;
  esac
}

while test "$#" -gt 0; do
  case "$1" in
    --adapter)
      test "$#" -ge 2 || fail "--adapter requires a value"
      adapter="$2"
      shift 2
      ;;
    --limit)
      test "$#" -ge 2 || fail "--limit requires a value"
      limit="$2"
      shift 2
      ;;
    --shards)
      test "$#" -ge 2 || fail "--shards requires a value"
      shard_count="$2"
      shift 2
      ;;
    --max-parallel)
      test "$#" -ge 2 || fail "--max-parallel requires a value"
      max_parallel="$2"
      shift 2
      ;;
    --repo)
      test "$#" -ge 2 || fail "--repo requires a value"
      repository="$2"
      shift 2
      ;;
    --check)
      check_only="true"
      shift
      ;;
    --yes)
      assume_yes="true"
      shift
      ;;
    --no-watch)
      watch_run="false"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

case "$adapter" in
  codex-cli) required_secret="OPENAI_API_KEY" ;;
  claude-cli) required_secret="ANTHROPIC_API_KEY" ;;
  *) fail "--adapter must be codex-cli or claude-cli" ;;
esac
is_positive_integer "$limit" || fail "--limit must be 1 or 2"
test "$limit" -le 2 || fail "--limit must be 1 or 2"
is_positive_integer "$shard_count" || fail "--shards must be between 1 and 16"
test "$shard_count" -le 16 || fail "--shards must be between 1 and 16"
is_positive_integer "$max_parallel" || fail "--max-parallel must be between 1 and 16"
test "$max_parallel" -le "$shard_count" || fail "--max-parallel cannot exceed --shards"

require_command gh
gh auth status >/dev/null 2>&1 || fail "GitHub CLI is not authenticated; run: gh auth login"

if test -z "$repository"; then
  repository="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi
case "$repository" in
  */*) ;;
  *) fail "--repo must use OWNER/REPO format" ;;
esac

default_branch="$(gh repo view "$repository" --json defaultBranchRef --jq '.defaultBranchRef.name')"
test -n "$default_branch" || fail "could not resolve the repository default branch"

environment_api="repos/$repository/environments/$environment_name"
custom_policies="$(gh api "$environment_api" --jq '.deployment_branch_policy.custom_branch_policies // false')"
test "$custom_policies" = "true" || fail "$environment_name must use selected branch deployment policies"

branch_policies="$(gh api "$environment_api/deployment-branch-policies" --paginate --jq '.branch_policies[].name')"
branch_allowed="false"
for policy in $branch_policies; do
  if test "$policy" = "$default_branch"; then
    branch_allowed="true"
  fi
done
test "$branch_allowed" = "true" || fail "$environment_name must explicitly allow the default branch: $default_branch"

enabled="$(gh variable get HOSTED_DETONATION_ENABLED --env "$environment_name" --repo "$repository" 2>/dev/null || true)"
test "$enabled" = "true" || fail "$environment_name variable HOSTED_DETONATION_ENABLED must equal true"

secret_names="$(gh secret list --env "$environment_name" --repo "$repository" --json name --jq '.[].name')"
secret_found="false"
for secret_name in $secret_names; do
  if test "$secret_name" = "$required_secret"; then
    secret_found="true"
  fi
done
test "$secret_found" = "true" || fail "$environment_name is missing environment secret $required_secret"

smoke_conclusion="$(gh run list --repo "$repository" --workflow evaluate-skillject.yml --limit 1 --json conclusion --jq '.[0].conclusion // empty')"
test "$smoke_conclusion" = "success" || fail "the latest hosted eBPF smoke run must succeed before detonation"
smoke_url="$(gh run list --repo "$repository" --workflow evaluate-skillject.yml --limit 1 --json url --jq '.[0].url // empty')"

can_admins_bypass="$(gh api "$environment_api" --jq '.can_admins_bypass // false')"
if test "$can_admins_bypass" = "true"; then
  printf 'warning: environment administrator bypass is enabled; disable it where your plan supports that control\n' >&2
fi

printf 'Hosted detonation preflight passed.\n'
printf '  Repository:   %s\n' "$repository"
printf '  Branch:       %s\n' "$default_branch"
printf '  Adapter:      %s\n' "$adapter"
printf '  Skills:       at most %s\n' "$((limit * shard_count))"
printf '  Runners:      %s shard(s), %s concurrent\n' "$shard_count" "$max_parallel"
printf '  Smoke test:   %s\n' "$smoke_url"

if test "$check_only" = "true"; then
  printf 'Check-only mode: no workflow was dispatched.\n'
  exit 0
fi

if test "$assume_yes" != "true"; then
  if test -t 0; then
    printf 'Dispatch provider-backed GitHub runners now? [y/N] '
    read -r answer
    case "$answer" in
      y|Y|yes|YES) ;;
      *) fail "dispatch cancelled" ;;
    esac
  else
    fail "non-interactive dispatch requires --yes"
  fi
fi

previous_run_id="$(gh run list --repo "$repository" --workflow detonate.yml --event workflow_dispatch --branch "$default_branch" --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
gh workflow run detonate.yml \
  --repo "$repository" \
  --ref "$default_branch" \
  --field "agent_adapter=$adapter" \
  --field "limit=$limit" \
  --field "shard_count=$shard_count" \
  --field "max_parallel=$max_parallel"

run_id=""
attempt="1"
while test "$attempt" -le 15; do
  candidate="$(gh run list --repo "$repository" --workflow detonate.yml --event workflow_dispatch --branch "$default_branch" --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
  if test -n "$candidate" && test "$candidate" != "$previous_run_id"; then
    run_id="$candidate"
    break
  fi
  sleep 2
  attempt="$((attempt + 1))"
done

test -n "$run_id" || fail "workflow was dispatched, but its run ID was not visible within 30 seconds"
run_url="$(gh run view "$run_id" --repo "$repository" --json url --jq '.url')"
printf 'Dispatched hosted detonation: %s\n' "$run_url"

if test "$watch_run" = "true"; then
  gh run watch "$run_id" --repo "$repository" --exit-status
fi

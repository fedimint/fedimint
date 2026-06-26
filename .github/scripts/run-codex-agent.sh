#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 1
  fi
}

require_env BACKPORT_TOKEN
require_env GITHUB_ACTOR
require_env GITHUB_EVENT_NAME
require_env GITHUB_EVENT_PATH
require_env GITHUB_REPOSITORY
require_env GITHUB_WORKSPACE
require_env PPQ_KEY
require_env RUNNER_TEMP

PPQ_MODEL="${PPQ_MODEL:-openai/gpt-5.5}"
agent_event_name="${CODEX_AGENT_EVENT_NAME:-${GITHUB_EVENT_NAME}}"
agent_event_path="${CODEX_AGENT_EVENT_PATH:-${GITHUB_EVENT_PATH}}"
agent_actor="${CODEX_AGENT_ACTOR:-${GITHUB_ACTOR}}"

if [ ! -s "${agent_event_path}" ]; then
  echo "Codex agent event payload does not exist or is empty: ${agent_event_path}" >&2
  exit 1
fi

agent_root="${RUNNER_TEMP}/codex-agent"
agent_home="${agent_root}/home"
codex_home="${agent_root}/codex-home"
context_dir="${agent_root}/context"

rm -rf "${agent_root}"
mkdir -p \
  "${agent_home}" \
  "${codex_home}" \
  "${context_dir}"

path_toml=$(jq -Rn --arg value "${PATH}" '$value')

# Security model: this job relies on the self-hosted runner's systemd
# isolation for process containment, and on Codex's shell environment policy
# to keep provider credentials out of agent-spawned commands.
cat > "${codex_home}/config.toml" <<EOF
model = "${PPQ_MODEL}"
model_provider = "ppq"
sandbox_mode = "danger-full-access"
approval_policy = "never"


[model_providers.ppq]
name = "PPQ"
base_url = "https://api.ppq.ai/v1"
env_key = "PPQ_KEY"
wire_api = "responses"


[shell_environment_policy]
inherit = "all"
ignore_default_excludes = true
set = { PATH = ${path_toml} }
include_only = [
  "PATH",
  "HOME",
  "CODEX_HOME",
  "GH_TOKEN",
  "GITHUB_API_URL",
  "GITHUB_ACTOR",
  "GITHUB_EVENT_NAME",
  "GITHUB_GRAPHQL_URL",
  "GITHUB_REPOSITORY",
  "GITHUB_RUN_ID",
  "GITHUB_SERVER_URL",
  "GITHUB_WORKSPACE",
  "RUNNER_TEMP",
  "IN_NIX_SHELL",
  "REPO_ROOT",
  "CARGO_*",
  "RUST*",
  "CLIPPY_ARGS",
  "FM_*",
  "FLAKEBOX_*",
  "NIX_*",
  "NIXPKGS_*",
  "CC*",
  "CXX*",
  "CFLAGS*",
  "CPPFLAGS",
  "CMAKE_*",
  "PKG_CONFIG*",
  "PROTOC*",
  "AR*",
  "AS",
  "LD",
  "LD_*",
  "LD_LIBRARY_PATH",
  "LIBCLANG_PATH",
  "LLVM_CONFIG_PATH*",
  "NM",
  "OBJCOPY",
  "OBJDUMP",
  "RANLIB",
  "READELF",
  "SIZE",
  "STRINGS",
  "STRIP",
  "ROCKSDB_*",
  "SNAPPY_*",
  "SQLITE3_*",
  "SQLCIPHER_*",
  "CONFIG_SHELL",
  "SHELL",
  "LANG",
  "LC_*",
  "LOCALE_ARCHIVE",
  "TERM",
  "TERMINFO_DIRS",
  "TMPDIR",
  "TEMP",
  "TMP",
  "TEMPDIR",
  "PYTHON*",
  "PERL5LIB",
  "XDG_CONFIG_DIRS",
  "XDG_DATA_DIRS",
  "DETERMINISTIC_BUILD",
  "SOURCE_DATE_EPOCH",
  "SSL_CERT_FILE",
  "NIX_SSL_CERT_FILE",
]
EOF

jq '{
  action,
  repository: env.GITHUB_REPOSITORY,
  event_name: $event_name,
  actor: $actor,
  comment: .comment,
  issue: .issue,
  pull_request: .pull_request,
  review: .review
}' \
  --arg event_name "${agent_event_name}" \
  --arg actor "${agent_actor}" \
  "${agent_event_path}" > "${context_dir}/event.json"

cat > "${context_dir}/prompt.md" <<'EOF'
You are fedimint-bot, an automation agent for the Fedimint GitHub repository.
An organization member invoked you by mentioning @fedimint-bot in a GitHub
issue, pull request, pull request review body, or pull request review thread;
by opening an issue that mentions @fedimint-bot; or by assigning an issue to
fedimint-bot. Decide what action is useful from the context.

You may:
- answer the question directly in the relevant GitHub thread;
- inspect the repository, PR diff, CI state, linked issues, or previous comments;
- do preliminary research and post findings;
- implement a small, low-risk fix, push a branch, and open a draft PR;
- open a follow-up issue when that is the most appropriate outcome.

Use judgment. Prefer a concise answer when the user is asking a question. Only
change code for simple, well-scoped fixes. Do not make broad refactors. Do not
push to contributor PR branches. If you implement a fix, create a new branch
named like `fedimint-bot/<short-topic>-<run-id>` and open a draft PR.

Write GitHub comments and PR descriptions in concise, scannable Markdown:
use short headings, bullets, code spans, and checklists when they make the
result easier to read. Avoid wall-of-text replies, but do not add filler.

Available tools:
- `gh`, authenticated as fedimint-bot via `GH_TOKEN`;
- `git`;
- normal shell tools including `bash`, `curl`, `jq`, `rg`, `sed`, and `awk`;
- the Fedimint Nix development shell, including its Rust toolchain and helper
  environment, is active for commands you run.

Repository conventions:
- Follow AGENTS.md and any nested repository instructions.
- For Rust code, avoid `unwrap()` in non-test code; use `expect()` with an
  invariant message or propagate errors.
- Use structured logging where relevant.
- Run `just format` after code changes if the toolchain is available.
- Run focused checks when practical and report what was or was not verified.

Operational rules:
- The GitHub event payload is at `$RUNNER_TEMP/codex-agent/context/event.json`.
- The checked out repository is at `$GITHUB_WORKSPACE`.
- The checkout includes recent history using partial clone filtering
  (`fetch-depth: 50` with `filter: blob:none`) to keep startup fast while
  preserving local context for common history lookups. If you need older
  history, tags, or PR refs, fetch only the specific refs you need.
- First inspect the normalized `event_name` field in the event payload to
  understand whether this is an issue event, issue comment, PR comment,
  submitted PR review, or inline PR review comment. Submitted PR reviews and
  inline PR review comments may arrive through a privileged follow-up workflow,
  but their payloads are normalized to `pull_request_review` or
  `pull_request_review_comment`.
- Use `gh` to fetch additional context as needed.
- For issue assignment events, treat the assignment as a request to open a
  small draft PR when the issue is well scoped and implementation is low risk.
- For inline PR review comments, get the pull request number from the event
  payload and use `gh api
  repos/:owner/:repo/pulls/:pull_number/comments/:comment_id/replies
  -f body=...` to reply directly to the review thread.
- If replying to an inline PR review comment returns 404, do not immediately
  fall back to a top-level PR comment. First fetch all review comments for the
  PR with `gh api --paginate repos/:owner/:repo/pulls/:pull_number/comments`,
  search for the event comment by `id`, `node_id`, `html_url`, file location,
  and body text, then retry the reply using the matched comment id if found.
- If responding to a pull request review comment, prefer replying to that
  review comment thread when possible. Otherwise comment on the issue or PR.
- If responding to a submitted pull request review body, prefer a top-level PR
  comment because GitHub does not expose a review-body reply thread.
- Before finishing, post a GitHub comment/reply, open a GitHub issue, or open a
  draft PR, unless the safest action is explicitly to do nothing.
- If you cannot complete the requested action, post a short comment explaining
  the blocker.
- Avoid mentioning secrets or environment variable values in comments, logs,
  commits, branches, or PR descriptions.
- Do not wait for human input; make a reasonable decision and act.
EOF

export HOME="${agent_home}"
export CODEX_HOME="${codex_home}"
export GH_TOKEN="${BACKPORT_TOKEN}"

git config --global --add safe.directory "${GITHUB_WORKSPACE}"
git config --global user.name fedimint-bot
git config --global user.email fedimint-bot@users.noreply.github.com
gh auth status >/dev/null
gh auth setup-git

cd "${GITHUB_WORKSPACE}"
# Deliberately bypass Codex's own sandbox here: the dedicated runner service
# provides systemd isolation, and shell_environment_policy keeps model/API
# secrets out of commands the agent runs.
exec codex exec \
  --ephemeral \
  --dangerously-bypass-approvals-and-sandbox \
  "$(cat "${context_dir}/prompt.md")"

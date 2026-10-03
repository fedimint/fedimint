#!/usr/bin/env bash
set -euo pipefail

digest_dir=${DIGEST_DIR:?Missing DIGEST_DIR}
runner_temp=${RUNNER_TEMP:?Missing RUNNER_TEMP}
workspace=${GITHUB_WORKSPACE:?Missing GITHUB_WORKSPACE}

deterministic_digest="${digest_dir}/deterministic.md"
state_json="${digest_dir}/state.json"
final_digest="${digest_dir}/digest.md"

if [ ! -s "${deterministic_digest}" ] || [ ! -s "${state_json}" ]; then
  echo "Digest inputs are missing" >&2
  exit 1
fi

if [ -z "${PPQ_KEY:-}" ]; then
  echo "PPQ_KEY is unavailable; publishing the deterministic digest"
  cp "${deterministic_digest}" "${final_digest}"
  exit 0
fi

agent_root="${runner_temp}/maintainer-digest-ai"
codex_home="${agent_root}/codex-home"
mkdir -p "${codex_home}"

path_toml=$(jq -Rn --arg value "${PATH}" '$value')
cat > "${codex_home}/config.toml" <<EOF
model = "${PPQ_MODEL:-openai/gpt-5.5}"
model_provider = "ppq"
model_reasoning_effort = "high"
sandbox_mode = "read-only"
approval_policy = "never"
hide_agent_reasoning = true

[model_providers.ppq]
name = "PPQ"
base_url = "https://api.ppq.ai/v1"
env_key = "PPQ_KEY"
wire_api = "responses"

[history]
persistence = "none"

[shell_environment_policy]
inherit = "none"
set = { PATH = ${path_toml} }
include_only = ["PATH", "HOME", "CODEX_HOME", "LANG", "LC_*", "TMPDIR"]
EOF

prompt_file="${agent_root}/prompt.md"
output_file="${agent_root}/ai-summary.md"
log_file="${agent_root}/codex.log"

{
  cat "${workspace}/.github/agents/maintainer-digest.md"
  printf '%s\n' \
    '' \
    '<trusted_snapshot_with_untrusted_string_values>'
  cat "${state_json}"
  printf '%s\n' '</trusted_snapshot_with_untrusted_string_values>'
} > "${prompt_file}"

export CODEX_HOME="${codex_home}"
# The summarizer has no GitHub task and must not inherit a token even when the
# wrapper is invoked outside the dedicated workflow step.
unset GH_TOKEN GITHUB_TOKEN
if ! codex exec \
  --ephemeral \
  --output-last-message "${output_file}" \
  - < "${prompt_file}" > "${log_file}" 2>&1; then
  echo "AI prioritization failed; publishing the deterministic digest" >&2
  tail -n 80 "${log_file}" >&2 || true
  cp "${deterministic_digest}" "${final_digest}"
  exit 0
fi

if [ ! -s "${output_file}" ]; then
  echo "AI prioritization was empty; publishing the deterministic digest" >&2
  cp "${deterministic_digest}" "${final_digest}"
  exit 0
fi

{
  cat "${output_file}"
  printf '%s\n' '' '---' ''
  cat "${deterministic_digest}"
} > "${final_digest}"

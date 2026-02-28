#!/usr/bin/env bash
# Debug a CI failure using Claude Code
#
# Usage:
#   ./scripts/debug-ci-failure.sh              # Debug most recent failure (local)
#   ./scripts/debug-ci-failure.sh <run-id>     # Debug specific run (local)
#   ./scripts/debug-ci-failure.sh --list       # List recent failures
#   ./scripts/debug-ci-failure.sh --ci <dir>   # CI mode: use pre-downloaded context

set -euo pipefail

# Colors for output (disabled in CI)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

usage() {
    echo "Usage: $0 [run-id|--list|--ci <dir>|--prompt <dir>|--help]"
    echo ""
    echo "Options:"
    echo "  <run-id>       Debug a specific GitHub Actions run"
    echo "  --list         List recent failed runs"
    echo "  --ci <dir>     CI mode: use pre-downloaded context from <dir>"
    echo "  --prompt <dir> Output the prompt only (for use with claude-code-action)"
    echo "  --help         Show this help message"
}

list_failures() {
    echo -e "${YELLOW}Recent failed CI runs:${NC}"
    echo ""
    gh run list \
        --status failure \
        --limit 10 \
        --json databaseId,displayTitle,workflowName,headBranch,createdAt,conclusion \
        --jq '.[] | "  \(.databaseId) | \(.workflowName) | \(.headBranch) | \(.createdAt | split("T")[0])"'
    echo ""
    echo "Run with a specific ID: $0 <run-id>"
}

generate_prompt() {
    local context_dir="$1"
    local run_info=""
    local failure_log=""
    local existing_issues=""

    # Read context files
    if [ -f "$context_dir/run-info.json" ]; then
        run_info=$(cat "$context_dir/run-info.json")
    fi
    if [ -f "$context_dir/failure.log" ]; then
        failure_log=$(cat "$context_dir/failure.log")
    fi
    if [ -f "$context_dir/existing-issues.json" ]; then
        existing_issues=$(cat "$context_dir/existing-issues.json")
    fi

    cat <<EOF
You are debugging a CI test failure for the Fedimint project.

## Context
$run_info

## Failure Logs
$failure_log

## Existing Open CI Issues
$existing_issues

## Your Task

1. **Read and analyze the failure:**
   - Identify which specific test(s) failed
   - Determine the root cause
   - Classify as: \`flaky-test\`, \`real-bug\`, \`infra-issue\`, or \`dependency-issue\`

2. **Check for existing issues:**
   - Look for issues that describe the SAME failure (same test, same error message pattern)
   - If a matching issue exists, note its number

3. **Take action based on your findings:**

   **If an existing issue matches this failure:**
   - Run: \`gh issue comment <issue-number> --body "<your-comment>"\`
   - Comment should include: timestamp, commit SHA, brief confirmation it's the same issue
   - Do NOT create a new issue

   **If this is a NEW failure (no matching issue):**
   - Run: \`gh issue create --title "<title>" --label "ci-failure" --label "<classification>" --body "<body>"\`
   - Title format: \`CI: <test-name> failing - <brief-description>\`
   - Body should include:
     - Summary of what failed
     - Error message/stack trace (truncated if long)
     - Root cause analysis
     - Suggested fix or investigation steps
     - Link to failed run

   **If this appears to be an infrastructure/transient issue:**
   - Do NOT create an issue
   - Just output your analysis

## Important Notes
- Be concise in issue descriptions - developers are experienced
EOF
}

run_claude_analysis() {
    local context_dir="$1"
    claude -p "$(generate_prompt "$context_dir")"
}

prepare_context_local() {
    local run_id="$1"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo -e "${GREEN}Fetching logs for run ${run_id}...${NC}"

    # Get run info
    gh run view "$run_id" --json jobs,conclusion,event,headBranch,headSha,url > "$tmp_dir/run-info.json" 2>&1 || true

    # Get failed logs
    gh run view "$run_id" --log-failed > "$tmp_dir/failure.log" 2>&1 || true

    # Truncate if too large
    if [ -f "$tmp_dir/failure.log" ]; then
        local log_size
        log_size=$(wc -c < "$tmp_dir/failure.log")
        if [ "$log_size" -gt 100000 ]; then
            echo -e "${YELLOW}Log is large (${log_size} bytes), truncating to last 100KB...${NC}"
            tail -c 100000 "$tmp_dir/failure.log" > "$tmp_dir/failure-truncated.log"
            mv "$tmp_dir/failure-truncated.log" "$tmp_dir/failure.log"
        fi
    fi

    # Get existing issues
    gh issue list \
        --label "ci-failure" \
        --state open \
        --limit 20 \
        --json number,title,body,labels,createdAt \
        > "$tmp_dir/existing-issues.json" 2>&1 || echo "[]" > "$tmp_dir/existing-issues.json"

    # Display run info
    echo ""
    echo -e "${GREEN}Run Info:${NC}"
    jq -r '"  Event: \(.event)\n  Branch: \(.headBranch)\n  Commit: \(.headSha)\n  URL: \(.url)"' "$tmp_dir/run-info.json" 2>/dev/null || echo "  Could not parse run info"
    echo ""

    echo "$tmp_dir"
}

debug_local() {
    local run_id="$1"

    # Check if claude is available
    if ! command -v claude &> /dev/null; then
        echo -e "${RED}Error: 'claude' command not found. Please install Claude Code.${NC}"
        exit 1
    fi

    local context_dir
    context_dir=$(prepare_context_local "$run_id")

    echo -e "${GREEN}Analyzing with Claude Code...${NC}"
    echo ""

    run_claude_analysis "$context_dir"

    # Cleanup
    rm -rf "$context_dir"
}

debug_ci() {
    local context_dir="$1"

    if [ ! -d "$context_dir" ]; then
        echo "Error: Context directory does not exist: $context_dir"
        exit 1
    fi

    run_claude_analysis "$context_dir"
}

# Main
case "${1:-}" in
    --help|-h)
        usage
        exit 0
        ;;
    --list|-l)
        list_failures
        exit 0
        ;;
    --ci)
        if [ -z "${2:-}" ]; then
            echo "Error: --ci requires a directory argument"
            usage
            exit 1
        fi
        debug_ci "$2"
        ;;
    --prompt)
        if [ -z "${2:-}" ]; then
            echo "Error: --prompt requires a directory argument" >&2
            usage
            exit 1
        fi
        generate_prompt "$2"
        ;;
    "")
        # Get most recent failure
        echo -e "${GREEN}Finding most recent failed run...${NC}"
        RUN_ID=$(gh run list --status failure --limit 1 --json databaseId -q '.[0].databaseId')
        if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
            echo -e "${YELLOW}No recent failures found.${NC}"
            exit 0
        fi
        echo -e "Found run: ${RUN_ID}"
        debug_local "$RUN_ID"
        ;;
    *)
        debug_local "$1"
        ;;
esac

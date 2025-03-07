#!/usr/bin/env bash

#############################
# Mock and Test Functions   #
#############################

# mock_nix_build simulates the behavior of `nix build`.
# It returns a dummy output path on success or fails when MOCK_NIX_BUILD_FAIL=1.
function mock_nix_build() {
    if [[ "${MOCK_NIX_BUILD_FAIL:-}" == "1" ]]; then
        return 1
    else
        # Simulate a successful build returning a dummy nix store path.
        echo "/nix/store/dummy"
    fi
}

# The test version of nix_build_binary_for_version which uses mock_nix_build instead of nix build.
function nix_build_binary_for_version_test() {
    local binary="$1"
    local version="$2"

    >&2 echo "Compiling ${binary} for version ${version} ..."
    # Use the mock; if it fails, print an error message and exit.
    output_path=$(mock_nix_build "$binary" "$version") || {
         >&2 echo "Error: nix build failed for $binary $version"
         exit 1
    }
    # On success, output the expected binary path.
    echo "${output_path}/bin/${binary}"
}

#############################
# Unit Test Infrastructure  #
#############################

# run_test runs a given test function by name and prints status.
function run_test() {
    local test_name="$1"
    shift
    echo "Running test: ${test_name}"
    "$@"
    echo "Test ${test_name} passed."
}

# capture_exit runs a command in a subshell and returns its exit code.
function capture_exit() {
    ( "$@" )
    return $?
}

#############################
# Unit Tests                #
#############################

# Test that a successful build returns the correct binary path.
function test_success() {
    # Ensure the mock does not simulate a failure.
    unset MOCK_NIX_BUILD_FAIL 2>/dev/null || true

    local result
    result=$(nix_build_binary_for_version_test "dummy_binary" "v1.0")
    local expected="/nix/store/dummy/bin/dummy_binary"

    if [[ "$result" != "$expected" ]]; then
        echo "Expected output '${expected}', got '${result}'" >&2
        exit 1
    fi
}

# Test that a failing build causes the function to exit with a non-zero code.
function test_failure_exit_code() {
    export MOCK_NIX_BUILD_FAIL=1

    # Disable -e temporarily to capture the non-zero exit code.
    set +e
    capture_exit nix_build_binary_for_version_test "dummy_binary" "v1.0"
    local exit_code=$?
    set -e

    if [[ $exit_code -eq 0 ]]; then
         echo "Expected non-zero exit code on failure, got ${exit_code}" >&2
         exit 1
    fi

    unset MOCK_NIX_BUILD_FAIL
}

# Test that the error message is printed to stderr when the build fails.
function test_failure_error_message() {
    export MOCK_NIX_BUILD_FAIL=1

    # Disable -e temporarily so that the expected failure doesn't abort the test.
    set +e
    local err_output
    err_output=$( { nix_build_binary_for_version_test "dummy_binary" "v1.0" 1>/dev/null; } 2>&1 )
    local exit_code=$?
    set -e

    if [[ $exit_code -eq 0 ]]; then
         echo "Expected non-zero exit code in test_failure_error_message" >&2
         exit 1
    fi

    if [[ "$err_output" != *"Error: nix build failed for dummy_binary v1.0"* ]]; then
         echo "Expected error message not found in stderr. Got: ${err_output}" >&2
         exit 1
    fi

    unset MOCK_NIX_BUILD_FAIL
}

# Test that even if the call site hasn't enabled strict modes (set -e), the function forces exit.
function test_call_site_without_strict() {
    # We embed our function definitions in a new bash instance via a heredoc.
    # In that shell we disable strict mode with 'set +e'. The test sets MOCK_NIX_BUILD_FAIL so that
    # nix_build_binary_for_version_test calls exit. If exit works, then any code following the function call (like "echo after call")
    # will never execute.
    local output exit_code
    set +e
  output=$(bash <<'EOF'
set +e
function mock_nix_build() {
    if [[ "${MOCK_NIX_BUILD_FAIL:-}" == "1" ]]; then
        return 1
    else
        echo "/nix/store/dummy"
    fi
}
function nix_build_binary_for_version_test() {
    local binary="$1"
    local version="$2"
    >&2 echo "Compiling ${binary} for version ${version} ..."
    output_path=$(mock_nix_build "$binary" "$version") || {
         >&2 echo "Error: nix build failed for $binary $version"
         exit 1
    }
    echo "${output_path}/bin/${binary}"
}
export MOCK_NIX_BUILD_FAIL=1
echo "calling nix_build_binary_for_version_test, expecting to fail"
nix_build_binary_for_version_test "dummy_binary" "v1.0"
echo "after call"
EOF
)
    exit_code=$?
    set -e

    echo "$output"

    if ! echo "$output" | grep -q "calling nix_build_binary_for_version_test, expecting to fail"; then
         echo "Call site did not exit as expected even without strict mode." >&2
         exit 1
    fi

    if echo "$output" | grep -q "after call"; then
         echo "Call site did not exit as expected even without strict mode." >&2
         exit 1
    fi

    if [[ $exit_code -eq 0 ]]; then
         echo "Expected non-zero exit code from bash instance, got $exit_code" >&2
         exit 1
    fi
}

#############################
# Run All Tests             #
#############################

run_test "test_success" test_success
run_test "test_failure_exit_code" test_failure_exit_code
run_test "test_failure_error_message" test_failure_error_message
run_test "test_call_site_without_strict" test_call_site_without_strict

echo "All tests passed."


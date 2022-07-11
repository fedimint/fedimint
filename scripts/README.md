# Shell Scripts
Here you can find scripts for running and testing Minimint:
* `build.sh` - Builds the rust executables and sets environment variables
* `setup-tests.sh` - Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes
* `start-fed.sh` - Generates the configs and starts the federation nodes
* `pegin.sh` - Calls the CLI to peg into the federation
* `rust-tests.sh` - Runs the all the Rust integration tests (required for PRs)
* `latency-test.sh` - Runs a test to determine the latency of certain user actions
* `cli-test.sh` - Runs a CLI-based integration test (required for PRs)
* `final-checks.sh` - Checks to run before opening a PR
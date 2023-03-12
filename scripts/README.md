# Shell Scripts
Here you can find scripts for running and testing Fedimint:
* `build.sh` - Builds the rust executables and sets environment variables
* `setup-tests.sh` - Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes
* `pegin.sh` - Calls the CLI to peg into the federation
* `rust-tests.sh` - Runs the all the Rust integration tests (required for PRs)
* `reconnect-test.sh` - Runs a test to see if peers that died can rejoin consensus
* `latency-test.sh` - Runs a test to determine the latency of certain user actions
* `cli-test.sh` - Runs a CLI-based integration test (required for PRs)
* `final-checks.sh` - Checks to run before opening a PR
* `tmux-user-shell.sh` - Helper script that prepares the tmuxinator setup (generate some blocks, fund wallet, …)
* `tmuxinator.sh` - Sets up a complete fedimint federation with Lightning gateway in tmux

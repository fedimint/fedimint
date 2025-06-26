# v0.7.0

* Partially automating docker setup testing https://github.com/fedimint/fedimint/pull/6742, https://github.com/fedimint/fedimint/pull/6922, https://github.com/fedimint/fedimint/pull/7059, https://github.com/fedimint/fedimint/pull/7042, https://github.com/fedimint/fedimint/pull/7069
* Better typed RPC errors in `PeerError` https://github.com/fedimint/fedimint/pull/6748
* Optimized fee estimation for lower on-chain fees https://github.com/fedimint/fedimint/pull/6749, https://github.com/fedimint/fedimint/pull/7012
* No longer return written bytes from `Encodable` trait https://github.com/fedimint/fedimint/pull/6754
* Logging verbosity adjustments https://github.com/fedimint/fedimint/pull/6773, https://github.com/fedimint/fedimint/pull/6772, https://github.com/fedimint/fedimint/pull/6775, https://github.com/fedimint/fedimint/pull/6786, https://github.com/fedimint/fedimint/pull/6787, https://github.com/fedimint/fedimint/pull/6792, https://github.com/fedimint/fedimint/pull/6809, https://github.com/fedimint/fedimint/pull/6847, https://github.com/fedimint/fedimint/pull/6859, https://github.com/fedimint/fedimint/pull/6984, https://github.com/fedimint/fedimint/pull/6997, https://github.com/fedimint/fedimint/pull/7017, https://github.com/fedimint/fedimint/pull/7028, https://github.com/fedimint/fedimint/pull/7082, https://github.com/fedimint/fedimint/pull/7092, https://github.com/fedimint/fedimint/pull/7153,
* 24h LN gateway payment statistics https://github.com/fedimint/fedimint/pull/6581
* Add timings to operation log entries https://github.com/fedimint/fedimint/pull/6771
* More efficient querying of the bitcoin blockchain data source https://github.com/fedimint/fedimint/pull/6770, https://github.com/fedimint/fedimint/pull/6819, https://github.com/fedimint/fedimint/pull/6818
* Ability to add API request hooks https://github.com/fedimint/fedimint/pull/6783
* Add `InPoint` as argument to `ServerModule::process_input` to allow modules to uniquely identify inputs https://github.com/fedimint/fedimint/pull/6799
* Make statistics about stored user backups available to guardians https://github.com/fedimint/fedimint/pull/6761, https://github.com/fedimint/fedimint/pull/7045
* Restructuring gateway code to split it into multiple crates for v1, v2 and core https://github.com/fedimint/fedimint/pull/6790, https://github.com/fedimint/fedimint/pull/6797, https://github.com/fedimint/fedimint/pull/6815, https://github.com/fedimint/fedimint/pull/6888,
* Document Lightning integration https://github.com/fedimint/fedimint/pull/6812, https://github.com/fedimint/fedimint/pull/6877
* Splitting `fedimint-client` and `fedimint-server` for more efficient compilation https://github.com/fedimint/fedimint/pull/6853, https://github.com/fedimint/fedimint/pull/6862, https://github.com/fedimint/fedimint/pull/6891, https://github.com/fedimint/fedimint/pull/6831, https://github.com/fedimint/fedimint/pull/7029
* More robust setup ceremony implementation https://github.com/fedimint/fedimint/pull/6827, https://github.com/fedimint/fedimint/pull/6940, https://github.com/fedimint/fedimint/pull/6702
* Stabilization of LNv2 https://github.com/fedimint/fedimint/pull/6781, https://github.com/fedimint/fedimint/pull/6906, https://github.com/fedimint/fedimint/pull/7035, https://github.com/fedimint/fedimint/pull/7034, https://github.com/fedimint/fedimint/pull/7149
* Beta support for the [Iroh overlay network](https://www.iroh.computer/), allowing to run `fedimintd` behind firewalls without opening ports https://github.com/fedimint/fedimint/pull/6878, https://github.com/fedimint/fedimint/pull/6915, https://github.com/fedimint/fedimint/pull/6901, https://github.com/fedimint/fedimint/pull/6917, https://github.com/fedimint/fedimint/pull/6926, https://github.com/fedimint/fedimint/pull/6923, https://github.com/fedimint/fedimint/pull/6929, https://github.com/fedimint/fedimint/pull/6942, https://github.com/fedimint/fedimint/pull/7150
* Drop official support for the `v0.2` and `v0.3` release branches https://github.com/fedimint/fedimint/pull/6916
* Fix memory leak in `TaskGroup` https://github.com/fedimint/fedimint/pull/6945
* Make `fedimint-cli` more robust against user input errors https://github.com/fedimint/fedimint/pull/6968, https://github.com/fedimint/fedimint/pull/7058
* Add DB integrity checks to detect potential invalid states early https://github.com/fedimint/fedimint/pull/6956
* Retire some of the obsolete helper docker images published in the past https://github.com/fedimint/fedimint/pull/6981
* Improved RPC error formatting https://github.com/fedimint/fedimint/pull/6979
* Add new Fedimint wallet Vipr to wallet list https://github.com/fedimint/fedimint/pull/6973
* Ability to override API endpoints of guardians using an environment variable https://github.com/fedimint/fedimint/pull/6978
* Remove CLN from CI environment, reducing the dev env size https://github.com/fedimint/fedimint/pull/6952, https://github.com/fedimint/fedimint/pull/6928, https://github.com/fedimint/fedimint/pull/7015
* Make DB migrations a closure instead of a function pointer, allowing capturing environment and abstract context https://github.com/fedimint/fedimint/pull/7016, https://github.com/fedimint/fedimint/pull/7022
* Make `Module` type available in `ServerModuleInit` trait https://github.com/fedimint/fedimint/pull/7014
* New integrated guardian UI https://github.com/fedimint/fedimint/pull/7033, https://github.com/fedimint/fedimint/pull/7041, https://github.com/fedimint/fedimint/pull/7093, https://github.com/fedimint/fedimint/pull/7103, https://github.com/fedimint/fedimint/pull/7098, https://github.com/fedimint/fedimint/pull/7104, https://github.com/fedimint/fedimint/pull/7115, https://github.com/fedimint/fedimint/pull/7122, https://github.com/fedimint/fedimint/pull/7133, https://github.com/fedimint/fedimint/pull/7130, https://github.com/fedimint/fedimint/pull/7146
* Add API to list Gateway Lightning transactions https://github.com/fedimint/fedimint/pull/7040
* Add `parse_invite_code` to client RPC to make it available in the WebSDK https://github.com/fedimint/fedimint/pull/7046
* Improve DB locking https://github.com/fedimint/fedimint/pull/7052
* Measure p2p and consensus latency https://github.com/fedimint/fedimint/pull/7066
* Add `parse_bolt11_invoice` to client RPC to make it available in the WebSDK https://github.com/fedimint/fedimint/pull/7079
* Lightning Gateway operator BOLT12 support https://github.com/fedimint/fedimint/pull/7054
* Add environment variable to override the esplora server to be used by the client to fetch blockchain data https://github.com/fedimint/fedimint/pull/7121
* Recurring receive support (initially LNURL, with option to add BOLT12 in the future) https://github.com/fedimint/fedimint/pull/6855
* Updated release process to have beta releases before RCs https://github.com/fedimint/fedimint/pull/7127, https://github.com/fedimint/fedimint/pull/7187
* Various dependency upgrades and minor bug fixes

# v0.6.2

* Fix `status` endpoint regression #7120
* Allow overwriting blockchain API supplied to clients #7124
* Add parse_invite_code function in fedimint-client-wasm #7116
* Expose additional backup metrics via prometheus #7053
* Fix potential client resource exhaustion  #7060

# v0.5.1

# v0.6.1

Fixes a regression in client DB.

# v0.6.0 - On-Chain for Everyone

Fedimint `v0.6.0` is here! :tada:

The on-chain wallet is no longer considered "expert-only."

Since `v0.4.0`, Fedimint developers advised not exposing on-chain deposits to end users, due to limitations on processing deposits in very large (in bytes) on-chain transactions. This limitations has been lifted and on-chain deposits are now safe in all cases.

Some other highlights since our last major (0.5) release:

- Federation will now reject attempt to reuse ecash blind nonces, preventing possibility of loss of funds even in the event of client-side bugs and data corruption, significantly increasing ecash robustness and funds safety.
- Fedimint will now query (configurable) external sources for feerate information to improve real time fee estimation.
- On-chain feerate multiplier have been lowered, as it no longer needs to be as conservative.
- LN payment events are now tracked, allowing tracking profit and fees statistics.
- It's now possible to customize  LNv2 gateway fees.
- Client recovery has been optimized and should be faster and use less data.
- Core lightning gateway is no longer supported.
- Work has been started on Iroh networking integration
- Fedimintd should use less memory now.

... and many, many internal changes and improvements. See [commit log](https://github.com/fedimint/fedimint/compare/v0.6.0...v0.5.0).

# v0.5.0 - Christmas Edition

Fedimint v0.5.0 is here! :tada:

Some highlights since our last major (0.4) release:
* Tor support for client-federation connections (see [`Connector` enum](https://docs.rs/fedimint-api-client/latest/fedimint_api_client/api/net/enum.Connector.html)) (thx @oleonardolima!)
* Stabilization of v2 of our lightning module. While not being rolled out by default yet integration and testing is encouraged. (thx @joschisan and @m1sterc001guy!)
* Upgraded rust-bitcoin (and related ecosystem-crates) from 0.30 to 0.32, which should be a [stable shelling point for the foreseeable future](https://github.com/rust-bitcoin/rust-bitcoin/issues/3166#issuecomment-2288739453) and leads fewer duplicates dependencies (thx @tvolk131!)
* Multiple bug fixes that were already backported to 0.3 and 0.4, but came out of refactoring and review work of modules (thx @bradleystachurski and @joschisan!)
* CI improvements to increase our agility while maintaining compatibility guarantees (thx @dpc and @bradleystachurski!)

As usual, there was lots more maintenance, debugging and integration going on in the background. Big thanks to everyone who contributes getting Fedimint closer to being the go-to, bulletproof community custody tool in Bitcoin!

I also asked GPT to summarize what else happened, ymmv:

### Features & Improvements
#### Lightning Network
- Preparation for BOLT12 invoice support
- Enhanced LNv2 module client API cleanup
- Improved LN module initialization and offline handling
- Gateway fee configuration improvements
- Fixed LDK create invoice issues
- Enhanced LN module thresholds handling

#### Performance & Optimization
- Faster consensus synchronization
    - Single session outcome request per session
    - Removed delay in signed session outcomes
- Optimized Rustls configuration
- Improved block sync and chain tracking
- Enhanced self-sync mechanism with checksum verification

#### Security & Authentication
- Made `sync_to_chain` authenticated
- Added security checks for ciphertext validation
- Improved secret hash comparison mechanisms

#### Developer Experience
- Added structured logging for devimint channel operations
- Improved cargo and git hash version handling
- Enhanced debugging tools for consensus issues
- Better panic messages and logging

#### Infrastructure
- Added support for WASM compilation
- Improved RocksDB implementation
- Added default BTC RPC environment variables in NixOS module
- Enhanced gateway registration process
- Better handling of dependencies and build profiles

#### Testing & CI
- Added gateway upgrade tests for LDK gateway
- Re-enabled LNv2 inter-federation tests
- Improved test shuffling for better coverage
- Enhanced upgrade testing framework

These changes appear to focus on improving Lightning Network functionality, system reliability, and developer tooling while maintaining security and performance optimizations.

# v0.4.4
# v0.4.3
# v0.4.2
# v0.4.1

This patch release fixes a bug when using esplora bitcoin backend.

[Please refer to v0.4.0 release notes for general v0.4 release information.](https://github.com/fedimint/fedimint/releases/tag/v0.4.0)


#  v0.4.0 - Rotation Station

⚠️ **CAUTION** ⚠️

Please refer to the upgrade docs for upgrading `fedimintd` older than 0.4.0. Clients are not effected.

https://github.com/fedimint/fedimint/blob/master/docs/RELEASE_NOTES-v0.4.md

## Release Notes


* Changing peer's DNS names is now possible.
* On chain deposits are now considered "expert-only" .
* On chain deposit charge fees by default to counter dust attacks.
* Wallet client module implements backup and recovery.
* Wallet client module is robust w.r.t deposit address reuse and rbf transactions.
* Client reconnection backoff was improved.
* RBF withdrawal functionality was removed.
* It's possible to finish DKG (setting up Federation) using only the `fedimint-cli` tool.

... and many, many internal changes and improvements.


#### On chain deposits are now considered "expert-only"

Given growing Fedimint usage, Fedimint developers officially recommend applications integrating fedimintd NOT to expose on-chain deposits to the end uses. LN Gateways and Mint guardians are recommended to use `fedimint-cli` to manage deposits.

In the near future we are planning to implement changes necessary to make on-chain deposits easy to use for all users. For further details, please refer to https://github.com/fedimint/fedimint/issues/5585.

####  Changing peer DNS names is now possible

Due to incidents where some Federations lost their guardian's DNS name and were unable to rotate DNS names, implementing a scheme that allows it was prioritized and implemented.

In the mid-term future we are planning to remove the DNS requirement altogether.

#### Wallet client module rewrite

The wallet client module was updated to accommodate deposit address reuse, rbf deposits, and streamline the backup and restore system.

# v0.3.1: Forward, backward, sideward compatibility? II
* Added Premetheus metrics
* Utils for fetching meta fields and vetted gateways (https://github.com/fedimint/fedimint/pull/4856)
* Minor fixes

## What's Changed
* Backport fix: bump wait_server_status timeout by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4731
* [Backport releases/v0.3] chore: add clap version command to all binaries by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4739
* [Backport releases/v0.3] chore(devimint): bump lnd polling to 60s by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4741
* [Backport releases/v0.3] chore(fedimint-cli): increase wait-block-count to 60s by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4747
* [Backport releases/v0.3] chore: make client task group available to modules by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4770
* [Backport releases/v0.3] chore: expose try_download_client_config by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4774
* chore(metrics): labeled grouped promethus metrics for wallet module  (Backport 4697 to releases/v0.3) by @dpc in https://github.com/fedimint/fedimint/pull/4758
* chore(metrics): labeled grouped prometehus metrics for wallet module (Backport 4696 to releases/v0.3) by @dpc in https://github.com/fedimint/fedimint/pull/4759
* [Backport releases/v0.3] chore(devimint): increase default poll timeout from 30s to 60s by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4833
* chore: bump h2 [backport] by @maan2003 in https://github.com/fedimint/fedimint/pull/4857
* [Backport releases/v0.3] chore(consensus): log items failing max size validation by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4902
* mass backport by @maan2003 in https://github.com/fedimint/fedimint/pull/4856
* backport: feat: gateway filter for update_gateway_cache_continuously by @maan2003 in https://github.com/fedimint/fedimint/pull/4906
* backport: fix: use u64 for attempts in fedimint retry by @maan2003 in https://github.com/fedimint/fedimint/pull/4933
* backport: chore: auto update on list-gateways  by @maan2003 in https://github.com/fedimint/fedimint/pull/4920
* chore: backport #4876 (update jsonrpsee) by @elsirion in https://github.com/fedimint/fedimint/pull/4980
* fix(recovery): can't recover without all server-side modules  (backport v0.3) by @dpc in https://github.com/fedimint/fedimint/pull/4987
* feat(nix): expose fedimintd NixOS module (v0.3 backport) by @dpc in https://github.com/fedimint/fedimint/pull/5062
* chore: bump to v0.3.1-rc.1 by @elsirion in https://github.com/fedimint/fedimint/pull/5030

**Full Changelog**: https://github.com/fedimint/fedimint/compare/v0.3.0...v0.3.1


# v0.3.0: Forward, backward, sideward compatibility?
## Upgrading
### `fedimintd`
* Stop all federation guardian `fedimintd`s
* Make a backup of the whole data dir (contains a bunch of JSON files and a `database` directory)
* Verify that all `fedimintd`s in the federation are off
* Upgrade the `fedimintd` binary through the deployment method of your choice
* Restart all `fedimintd`s
* Verify in the admin UI or via `fedimint-cli` that all of them are online again and making progress producing sessions

Note that, when upgrading from 0.2, you will not get the new Meta module, which otherwise gets added automatically to new setups now. In 0.4 we will add functionality that will allow retroactively adding the module. For compatibility with old clients it is still advised to use the `meta_override_url` field.

### Clients
Just using the new version of the client library should do. There were some rust interface changes, especially around LN gateways, but nothing too major. Reach out on GitHub or [Discord](https://chat.fedimint.org) if anything is unclear.

## Downgrading
Downgrading to previous versions is unsupported and will likely fail.

## What's Changed

### New Features:
* Dynamic meta fields through the Meta module
* Improved load-test-metrics for better performance insights.
* Capability to pass --auth flag to fedimint-cli dev api.
* Added recovery tool tests for enhanced reliability.
* Enhanced LN payments privacy for LND.
* CLI improvements and more configurable options.
* Added support to pay a lnurls.
* Implemented a special case descriptor for single-guardian instances for smaller on-chain transactions.
* Introduced versioned Gateway API for backward compatibility.
* Introduced a latency test for restore functions.

### Fixes and Updates:
* Introduced a simplification for always proposing block height and feerate votes.
* Multiple fixes including singular naming in MintOperationMetaVariant, serialization of enums in snake case for API consistency and adjustment for HTLC processing.
* Addressing warnings and errors for more robust operations and deployment.
* Various fixes to ensure compatibility and optimization across different platforms, networking conditions and operational scenarios.
* Database migrations for consistency and performance.
* Client-side transaction size checks to prevent unexpected server-side rejections

### Chore and Maintenance:
* Several chores to clean up code, improve build and testing processes, and update dependencies.
  *Introduction of concurrency and latency optimizations.
* Documentation improvements including more information on cargo packages and updating READMEs.
* Refactoring efforts for cleaner and more maintainable code design.

### Security:
* Updated dependencies and code changes to address known vulnerabilities.

### Detailed list of PRs:
* chore: move to self-published version of ldk-node by @elsirion in https://github.com/fedimint/fedimint/pull/3719
* chore: ensure prefix `fedimint` on all published crates by @elsirion in https://github.com/fedimint/fedimint/pull/3721
* feat: improved load-test-metrics by @douglaz in https://github.com/fedimint/fedimint/pull/3717
* Fixes I had to apply to 0.2 to be able to release Fedimint on crates.io by @elsirion in https://github.com/fedimint/fedimint/pull/3729
* chore: suppress tx already submitted error logs by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3733
* feat: read git hash from .cargo_vcs_info.json if compiling release by @elsirion in https://github.com/fedimint/fedimint/pull/3735
* fix: `MintOperationMetaVariant` uses singular name by @elsirion in https://github.com/fedimint/fedimint/pull/3734
* fix(cln-extension): avoid holding the sender lock during HTLC processing by @douglaz in https://github.com/fedimint/fedimint/pull/3742
* fix: use 33 byte tweaks in recovery tool parser by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3746
* chore: ignore uncommitted dbtx writes for endpoint audits by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3756
* fedimint-client secret derivation path in fedimint-CLI by @shaurya947 in https://github.com/fedimint/fedimint/pull/3740
* fix(api): serialize enums in snake case by @elsirion in https://github.com/fedimint/fedimint/pull/3761
* fix: give gateway test more time to send/receive money by @elsirion in https://github.com/fedimint/fedimint/pull/3762
* chore(deps): bump cachix/install-nix-action from 23 to 24 by @dependabot in https://github.com/fedimint/fedimint/pull/3769
* chore(deps): bump cachix/cachix-action from 12 to 13 by @dependabot in https://github.com/fedimint/fedimint/pull/3770
* simplification: always propose block height and feerate votes by @joschisan in https://github.com/fedimint/fedimint/pull/3758
* fix: avoid warnings on recovery from mid session crash by @joschisan in https://github.com/fedimint/fedimint/pull/3775
* chore: add repo link to `Cargo.toml` of published crates by @elsirion in https://github.com/fedimint/fedimint/pull/3776
* fix: nix advisory db update by @douglaz in https://github.com/fedimint/fedimint/pull/3780
* Use IPV4 in tls-download-mutinynet.sh by @TonyGiorgio in https://github.com/fedimint/fedimint/pull/3783
* feat: can pass --auth flag to `fedimint-cli dev api` by @justinmoon in https://github.com/fedimint/fedimint/pull/3749
* feat: added recoverytool tests by @douglaz in https://github.com/fedimint/fedimint/pull/3777
* fix: dont require muc.xmpp as a traefik router by @otech47 in https://github.com/fedimint/fedimint/pull/3800
* fix 'withdraw all' feature by @justinmoon in https://github.com/fedimint/fedimint/pull/3755
* chore: lower cpu use when consensus is running locally in dev profile by @dpc in https://github.com/fedimint/fedimint/pull/3801
* fix: allow `mainnet` as a valid network by @douglaz in https://github.com/fedimint/fedimint/pull/3811
* fix: only send authentication to one peer by @elsirion in https://github.com/fedimint/fedimint/pull/3785
* feat: make FM_NUMBER_OF_ROUTE_HINTS default more explicit by @justinmoon in https://github.com/fedimint/fedimint/pull/3814
* chore: improve organization of ./devimint by @mayrf in https://github.com/fedimint/fedimint/pull/3798
* chore: log successful ln-gateway withdrawal by @mayrf in https://github.com/fedimint/fedimint/pull/3818
* chore: remove unneeded network_to_currency by @benthecarman in https://github.com/fedimint/fedimint/pull/3819
* fix(fedimint-cli): create data dir if doesn't exist by @dpc in https://github.com/fedimint/fedimint/pull/3825
* chore: make `just mprocs` parametric by @elsirion in https://github.com/fedimint/fedimint/pull/3827
* fix: make client less verbose by @elsirion in https://github.com/fedimint/fedimint/pull/3830
* Make LN payments more private by @elsirion in https://github.com/fedimint/fedimint/pull/3816
* fix(gateway): disconnect before changing the network by @douglaz in https://github.com/fedimint/fedimint/pull/3833
* refactor: consensus_encode_to_vec can't fail by @dpc in https://github.com/fedimint/fedimint/pull/3832
* fix: don't depend on std features from lightning-invoice by @elsirion in https://github.com/fedimint/fedimint/pull/3839
* chore: refactor invoice expiration check in client by @TonyGiorgio in https://github.com/fedimint/fedimint/pull/3845
* feat(wallet): special-case descriptor for single-guardian instances by @elsirion in https://github.com/fedimint/fedimint/pull/3821
* chore: bundle per-binary debs and rpms by @dpc in https://github.com/fedimint/fedimint/pull/3836
* chore: update nix flakes by @douglaz in https://github.com/fedimint/fedimint/pull/3850
* Update tls-download-mutinynet.sh to reflect snake case awaiting_password by @TonyGiorgio in https://github.com/fedimint/fedimint/pull/3851
* chore: change info endpoint http method to get by @mayrf in https://github.com/fedimint/fedimint/pull/3847
* feat(fedimint-cli): added support to pay a lnurl by @douglaz in https://github.com/fedimint/fedimint/pull/3848
* Get rid of needless nixpkgs by @dpc in https://github.com/fedimint/fedimint/pull/3823
* fix(gateway): allow setting configuration when disconnected by @douglaz in https://github.com/fedimint/fedimint/pull/3855
* chore: display message warning about docstring requirements by @dpc in https://github.com/fedimint/fedimint/pull/3824
* feat: `just backport-pr` by @dpc in https://github.com/fedimint/fedimint/pull/3861
* fix(cli): increase deposit timeout and make it configurable by @elsirion in https://github.com/fedimint/fedimint/pull/3864
* Increase BYTE_LIMIT to 50k by @shaurya947 in https://github.com/fedimint/fedimint/pull/3867
* feat: ability to customize version string when building custom bins  by @dpc in https://github.com/fedimint/fedimint/pull/3858
* chore: change warning to a info by @douglaz in https://github.com/fedimint/fedimint/pull/3873
* test: verify recoverytool includes change outputs by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3865
* CLI: split and combine e-cash by @elsirion in https://github.com/fedimint/fedimint/pull/3879
* chore: change some errors to warns/infos by @douglaz in https://github.com/fedimint/fedimint/pull/3885
* fix: wasm-bindgen 0.2.88 was yanked by @dpc in https://github.com/fedimint/fedimint/pull/3877
* fix(devimint): off-by-one error for mempool transactions by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3893
* refactor(devimint): add get_block_count to bitcoind by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3898
* fix: supply LN invoice features to LN gateway node by @elsirion in https://github.com/fedimint/fedimint/pull/3896
* refactor: amount improvements by @douglaz in https://github.com/fedimint/fedimint/pull/3889
* feat: GlobalClientConfig::federation_name() by @justinmoon in https://github.com/fedimint/fedimint/pull/3908
* chore: deprecate DatabaseSource::Reuse by @dpc in https://github.com/fedimint/fedimint/pull/3913
* fix: make OOB spend cancellation reliable by @elsirion in https://github.com/fedimint/fedimint/pull/3900
* Make CLI spend e-cash more configurable by @elsirion in https://github.com/fedimint/fedimint/pull/3902
* feat: add span for showing operation_id in state machine transition by @maan2003 in https://github.com/fedimint/fedimint/pull/3921
* fix: prevent multiple backport workflows per branch by @bradleystachurski in https://github.com/fedimint/fedimint/pull/3926
* feat(devimint): `devimint version-hash` by @dpc in https://github.com/fedimint/fedimint/pull/3928
* chore: use larger amounts in tests by @shaurya947 in https://github.com/fedimint/fedimint/pull/3872
* feat: better invoice expiration by @douglaz in https://github.com/fedimint/fedimint/pull/3927
* feat(ln-client): make LN gateway known upfront by @elsirion in https://github.com/fedimint/fedimint/pull/3882
* build(deps): bump `fedimint-core` and `fedimint-load-test-tool` jsonrpsee to `0.21.0` by @oleonardolima in https://github.com/fedimint/fedimint/pull/3934
* chore: refactor `Client` initialization by @dpc in https://github.com/fedimint/fedimint/pull/3918
* fix: more robust lightning receive by @douglaz in https://github.com/fedimint/fedimint/pull/3929
* fix(mint-client): invalidate all spent notes on recovery by @elsirion in https://github.com/fedimint/fedimint/pull/3942
* Make devimint tmp dir much smaller by @dpc in https://github.com/fedimint/fedimint/pull/3932
* build(deps): bump actions/upload-artifact from 3 to 4 by @dependabot in https://github.com/fedimint/fedimint/pull/3948
* fix(client): missing expiry time by @douglaz in https://github.com/fedimint/fedimint/pull/3955
* chore: give build instructions to docs.rs by @elsirion in https://github.com/fedimint/fedimint/pull/3952
* fix: retry funding offer by @maan2003 in https://github.com/fedimint/fedimint/pull/3959
* fix(lightning): proper handle timeouts while receiving a payment by @douglaz in https://github.com/fedimint/fedimint/pull/3963
* test: latency of internal payments within fed by @okjodom in https://github.com/fedimint/fedimint/pull/3964
* chore: update zerocopy to fix vulnerability by @douglaz in https://github.com/fedimint/fedimint/pull/3972
* fix: client detects too big transactions and rejects them by @elsirion in https://github.com/fedimint/fedimint/pull/3953
* chore: fix `nix flake show .#` by @dpc in https://github.com/fedimint/fedimint/pull/3973
* chore: separate fedimint config info from gateway info endpoint by @mayrf in https://github.com/fedimint/fedimint/pull/3880
* feat: added comment/description for lnurl invoices by @douglaz in https://github.com/fedimint/fedimint/pull/3971
* feat: latency test for restore by @maan2003 in https://github.com/fedimint/fedimint/pull/3956
* fix: prevent spamming blockchain.info with requests by @dpc in https://github.com/fedimint/fedimint/pull/3969
* fix: wasm dev shell on macos by @dpc in https://github.com/fedimint/fedimint/pull/3986
* feat: more server metrics by @douglaz in https://github.com/fedimint/fedimint/pull/3975
* chore: `nix flake update` by @justinmoon in https://github.com/fedimint/fedimint/pull/4005
* feat: Return preimage when creating ln invoice by @benthecarman in https://github.com/fedimint/fedimint/pull/3997
* chore: fix some typos in the database structs by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4008
* chore: remove hbbft by @tvolk131 in https://github.com/fedimint/fedimint/pull/3993
* refactor: remove in-built client in devimint fed by @okjodom in https://github.com/fedimint/fedimint/pull/3698
* fix: add exponential backoff to autocommit with random delay by @maan2003 in https://github.com/fedimint/fedimint/pull/4015
* chore: add more logging to SM notifier by @elsirion in https://github.com/fedimint/fedimint/pull/4003
* fix: re-register gateway when routing fees are updated by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4020
* chore: add Readme.md links in each Cargo.toml by @15IITian in https://github.com/fedimint/fedimint/pull/4030
* feat: restart federation setup by @okjodom in https://github.com/fedimint/fedimint/pull/3669
* build(deps): bump cachix/cachix-action from 13 to 14 by @dependabot in https://github.com/fedimint/fedimint/pull/4032
* build(deps): bump cachix/install-nix-action from 24 to 25 by @dependabot in https://github.com/fedimint/fedimint/pull/4033
* fix: incorrect URL for Launch Lightning Gateway in Mutinynet setup guide by @wqxoxo in https://github.com/fedimint/fedimint/pull/4036
* chore(ci): upload release artifacts on tag builds by @dpc in https://github.com/fedimint/fedimint/pull/4023
* chore: upgrade tonic_lnd to 0.2.0 by @elsirion in https://github.com/fedimint/fedimint/pull/4031
* refactor: rename server db migrations by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4011
* fix: RUSTSEC-2024-0003 by @maan2003 in https://github.com/fedimint/fedimint/pull/4058
* chore(fedimintd): fix description of Cargo.toml by @15IITian in https://github.com/fedimint/fedimint/pull/4069
* chore: add description in Cargo.toml by @15IITian in https://github.com/fedimint/fedimint/pull/4071
* feat: reexport lightning_invoice and bitcoin by @benthecarman in https://github.com/fedimint/fedimint/pull/4065
* Cache session outcome count by @elsirion in https://github.com/fedimint/fedimint/pull/4072
* refactor: Only load federation clients when gateway boots by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4026
* chore(flake): expose fedimint-dbtool output by @dpc in https://github.com/fedimint/fedimint/pull/4075
* build(deps): bump actions/cache from 3 to 4 by @dependabot in https://github.com/fedimint/fedimint/pull/4053
* refactor: 0.2.1, and 0.1 docker scripts by @Kodylow in https://github.com/fedimint/fedimint/pull/4025
* chore: add Relative path of root README.md by @15IITian in https://github.com/fedimint/fedimint/pull/4038
* fix RUSTSEC-2024-0006 by @maan2003 in https://github.com/fedimint/fedimint/pull/4090
* fix: mark JsonRpcClientError:Call as retryable regardless of code by @shaurya947 in https://github.com/fedimint/fedimint/pull/4097
* test: Run Dummy Migration Tests by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4018
* refactor: Lightning Dir for Gateway by @Kodylow in https://github.com/fedimint/fedimint/pull/4081
* docs: readme updates remove 0.1 and clovyr broken links by @Kodylow in https://github.com/fedimint/fedimint/pull/4102
* chore: add module dkg message by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4055
* refactor: tbs by @joschisan in https://github.com/fedimint/fedimint/pull/4009
* refactor: client error handling by @dpc in https://github.com/fedimint/fedimint/pull/4064
* chore: client module recovery refactor by @dpc in https://github.com/fedimint/fedimint/pull/4035
* chore: better (hopefully) lock file handling by @dpc in https://github.com/fedimint/fedimint/pull/4106
* fix: use fedimint-aleph-bft by @maan2003 in https://github.com/fedimint/fedimint/pull/4116
* chore: store Lightning Gateway Registrations by gateway id by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4114
* chore: rm unused wasm tests cargo.lock by @maan2003 in https://github.com/fedimint/fedimint/pull/4118
* feat: versioned gateway api by @okjodom in https://github.com/fedimint/fedimint/pull/4000
* feat: stream blocks in new refactoring of mint module recovery by @dpc in https://github.com/fedimint/fedimint/pull/4042
* fix: downgrade alephbft by @maan2003 in https://github.com/fedimint/fedimint/pull/4135
* feat: expose pending accepted items in api for recovery and debugging. by @joschisan in https://github.com/fedimint/fedimint/pull/4133
* fix: make single guardian devimint cli test backwards-compatible by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4104
* Add backwards-compatible test matrix by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4010
* feat: await_block LRU cache (non-global)  by @dpc in https://github.com/fedimint/fedimint/pull/4080
* chore(fedimint-cli): convert invalid JSON data to JSON string by @15IITian in https://github.com/fedimint/fedimint/pull/4088
* build(deps): bump cachix/cachix-action from 13 to 14 by @dependabot in https://github.com/fedimint/fedimint/pull/4142
* chore: disable discord alerts for backwards-compatibility by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4139
* build(deps): bump cachix/install-nix-action from 24 to 25 by @dependabot in https://github.com/fedimint/fedimint/pull/4141
* fix: ignore TracingSetup error in migration tests by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4146
* chore: delete incorrect argument by @dpc in https://github.com/fedimint/fedimint/pull/4147
* fix: correct description of `fedimint-build` & `fedimint-server` by @15IITian in https://github.com/fedimint/fedimint/pull/4074
* feat(dbtool): delete whole key ranges by @elsirion in https://github.com/fedimint/fedimint/pull/4140
* fix: handle write write conflicts in mem db by @maan2003 in https://github.com/fedimint/fedimint/pull/3989
* fix: make gateway api backwards-compatible by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4136
* chore: specialize `Encodable`/`Decodable` for bytes by @dpc in https://github.com/fedimint/fedimint/pull/4145
* fix: make devimint backup & restore test backwards-compatible by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4166
* chore: Client Database Migrations (without state machine migrations) by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4103
* cleanup: remove redundant session counter from db by @joschisan in https://github.com/fedimint/fedimint/pull/4159
* refactor: remove unused error paths, use expect when possible by @joschisan in https://github.com/fedimint/fedimint/pull/4154
* Better gatewayd logs by @maan2003 in https://github.com/fedimint/fedimint/pull/4175
* fix: remove racy endpoint PENDING_ACCEPTED_ITEMS_ENDPOINT for SESSION_STATUS_ENDPOINT by @joschisan in https://github.com/fedimint/fedimint/pull/4150
* refactor: generic framework for from-history module recoveries by @dpc in https://github.com/fedimint/fedimint/pull/4137
* feat: refactor devimint into a library by @maan2003 in https://github.com/fedimint/fedimint/pull/4176
* fix: make set_active_gateway concurrency safe by @maan2003 in https://github.com/fedimint/fedimint/pull/4162
* chore: re-enable discord alerts for backwards-compatibility by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4177
* fix(justfile): don't use `cargo -p` by @dpc in https://github.com/fedimint/fedimint/pull/4184
* fix: add bitcoind to 0.2.1 mutinynet docker compose by @Kodylow in https://github.com/fedimint/fedimint/pull/4164
* chore: during dkg generate peer-ids by peer name ordering by @dpc in https://github.com/fedimint/fedimint/pull/4178
* chore(ci): cancel previous CI build if new one was submitted by @dpc in https://github.com/fedimint/fedimint/pull/4199
* fix: calculate the batches per sessions correctly to achieve fault tolerance by @joschisan in https://github.com/fedimint/fedimint/pull/4188
* fix: remove non-fault tolerant query strategy by @joschisan in https://github.com/fedimint/fedimint/pull/4189
* fix: pre-commit modified manually by @dpc in https://github.com/fedimint/fedimint/pull/4219
* chore(flake): `nix flake update` by @dpc in https://github.com/fedimint/fedimint/pull/4200
* fix: bump retry count for test_gateway_configuration by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4172
* fix: poll in reconnect test by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4220
* fix: justfile uses import instead of \!include by @elsirion in https://github.com/fedimint/fedimint/pull/4228
* chore: print more useful error message on enum decode errors by @elsirion in https://github.com/fedimint/fedimint/pull/4061
* fix: add fedimint-dbtool version-hash by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4232
* chore(ln-client): improve logging when choosing gateway by @elsirion in https://github.com/fedimint/fedimint/pull/4229
* chore: remove Garbage Collection ;) by @dpc in https://github.com/fedimint/fedimint/pull/4227
* chore: clean up documentation for `ILnRpcClient` by @tvolk131 in https://github.com/fedimint/fedimint/pull/4233
* chore: update macos github runners to m1-based `macos-14` by @justinmoon in https://github.com/fedimint/fedimint/pull/4235
* feat(mint-client): include federation join info in `OOBNotes` by @elsirion in https://github.com/fedimint/fedimint/pull/4231
* chore: improve devimint api by @maan2003 in https://github.com/fedimint/fedimint/pull/4237
* fix: fail to upload debs/rpms bundle on master by @dpc in https://github.com/fedimint/fedimint/pull/4244
* chore: update flakebox to remove a workaround by @dpc in https://github.com/fedimint/fedimint/pull/4245
* cleanup: remove unused error paths and consistently retry all errors by @joschisan in https://github.com/fedimint/fedimint/pull/4221
* chore: Migrate `DatabaseVersion` to global namespace by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4192
* Document fedimintd/src/fedimintd.rs by @isaack-njama in https://github.com/fedimint/fedimint/pull/4113
* chore(ci): test dev shell building by @dpc in https://github.com/fedimint/fedimint/pull/4256
* chore: collect env variables in `envs.rs` modules by @dpc in https://github.com/fedimint/fedimint/pull/4248
* fix: raw bytes Debug formatting by @dpc in https://github.com/fedimint/fedimint/pull/4255
* chore: add backwards compatibility test as just command by @elsirion in https://github.com/fedimint/fedimint/pull/4263
* chore: make debug statement more informative by @15IITian in https://github.com/fedimint/fedimint/pull/4240
* fix: document consensus by @joschisan in https://github.com/fedimint/fedimint/pull/4270
* chore: document version an endpoint was introduced in ... by @dpc in https://github.com/fedimint/fedimint/pull/4267
* Add doc strings to gateway/ln-gateway/src/bin/gatewayd.rs by @okjodom in https://github.com/fedimint/fedimint/pull/4063
* refactor(nix): split workspaceCov into separate build and test steps by @dpc in https://github.com/fedimint/fedimint/pull/4277
* chore: check out if nix-fast-build would work for us by @dpc in https://github.com/fedimint/fedimint/pull/4258
* test gateway fees and revise docker defaults by @okjodom in https://github.com/fedimint/fedimint/pull/4108
* chore: remove unused constants by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4288
* feat: decoding of url-safe base64 encoding for oobnotes by @dpc in https://github.com/fedimint/fedimint/pull/4259
* feat: wasm test concurrency by @maan2003 in https://github.com/fedimint/fedimint/pull/4291
* chore(portalloc): increase port allocation time by @dpc in https://github.com/fedimint/fedimint/pull/4299
* fix: broken db backward compat (MintRestoreStateMachine) by @dpc in https://github.com/fedimint/fedimint/pull/4274
* cleanup: remove operation id argument from await_tx_accepted by @joschisan in https://github.com/fedimint/fedimint/pull/4296
* fix: remove random timeout from download of client config by @joschisan in https://github.com/fedimint/fedimint/pull/4261
* chore: anti-flakiness spring offensive by @dpc in https://github.com/fedimint/fedimint/pull/4278
* fix: possible panic on server shutdown by @dpc in https://github.com/fedimint/fedimint/pull/4298
* chore: ignore TracingSetup test in client db migration tests by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4311
* feat: wasm ecash tests by @maan2003 in https://github.com/fedimint/fedimint/pull/4304
* chore: give macos-14 runner some time to cross-compile everything by @dpc in https://github.com/fedimint/fedimint/pull/4316
* fix: switch back to `nix build` for release builds on master by @dpc in https://github.com/fedimint/fedimint/pull/4314
* fix(ci): typo, failing master branch build by @dpc in https://github.com/fedimint/fedimint/pull/4321
* chore: verify_gateway_rpc_success and verify_gateway_rpc_failure by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4310
* chore: try to re-enable test_can_change_routing_fees by @dpc in https://github.com/fedimint/fedimint/pull/4322
* chore: skip rust_unit_tests in backwards-compatibility tests by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4323
* fix: build containers with normal `nix build` by @dpc in https://github.com/fedimint/fedimint/pull/4324
* fix(ci): don't use nix-fast-build for x-compiling on macos by @dpc in https://github.com/fedimint/fedimint/pull/4336
* fix(memdb): waaay too slow, at least use rwlock by @dpc in https://github.com/fedimint/fedimint/pull/4329
* chore: Notifier::notify improve logging by @dpc in https://github.com/fedimint/fedimint/pull/4330
* chore: add highest-level logs to sends_ecash_out_of_band by @dpc in https://github.com/fedimint/fedimint/pull/4333
* chore: no longer dead code by @dpc in https://github.com/fedimint/fedimint/pull/4334
* fix: recognise vetted gateways configured in base meta by @okjodom in https://github.com/fedimint/fedimint/pull/4138
* chore: improve autocommit error debug messages by @dpc in https://github.com/fedimint/fedimint/pull/4331
* chore: better consensus item formatting by @dpc in https://github.com/fedimint/fedimint/pull/4332
* fix(ci): androideabi -> android in exclude list by @dpc in https://github.com/fedimint/fedimint/pull/4337
* chore: poll longer in devimint by @dpc in https://github.com/fedimint/fedimint/pull/4344
* fix: stackoverflow link returns 403 in CI check by @dpc in https://github.com/fedimint/fedimint/pull/4345
* refactor(flake): export our overlays by @dpc in https://github.com/fedimint/fedimint/pull/4347
* refactor: improve client executor loop by @dpc in https://github.com/fedimint/fedimint/pull/4230
* fix: wait longer for lnd startup in reconnection test by @dpc in https://github.com/fedimint/fedimint/pull/4351
* chore: remove unneeded clippy exceptions by @tvolk131 in https://github.com/fedimint/fedimint/pull/4359
* feat(flake): use `sccache` in the dev shell by @dpc in https://github.com/fedimint/fedimint/pull/4360
* fix: remove use of system time in ln client by @benthecarman in https://github.com/fedimint/fedimint/pull/4356
* feat: simple release signing system by @dpc in https://github.com/fedimint/fedimint/pull/4339
* chore: re-enable sends_ecash_out_of_band_cancel by @dpc in https://github.com/fedimint/fedimint/pull/4320
* chore: remove unused `GatewayRequest` struct by @tvolk131 in https://github.com/fedimint/fedimint/pull/4358
* fix: gitignore mistake for `releases/bins` by @dpc in https://github.com/fedimint/fedimint/pull/4367
* feat: save invite code for each guardian by @kernelkind in https://github.com/fedimint/fedimint/pull/4318
* chore: migrate to miniscript v10 by @tvolk131 in https://github.com/fedimint/fedimint/pull/4086
* feat: Impl Eq & PartialEq for OOBNotes by @benthecarman in https://github.com/fedimint/fedimint/pull/4346
* fix: recovery waiting for the last session to close (mostly in tests)  by @dpc in https://github.com/fedimint/fedimint/pull/4148
* chore(nix): export gateway-cln-extension binary by @dpc in https://github.com/fedimint/fedimint/pull/4373
* chore: more wasm tests by @maan2003 in https://github.com/fedimint/fedimint/pull/4328
* chore: add single peer request strategy by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4361
* fix: flaky latency test by @dpc in https://github.com/fedimint/fedimint/pull/4381
* chore: client state machine migrations by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4282
* feat: immutable data structure for memdb by @maan2003 in https://github.com/fedimint/fedimint/pull/4335
* refactor(nix): split-out overlays into own files by @dpc in https://github.com/fedimint/fedimint/pull/4375
* chore: include PR titles in failed backport issues by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4382
* chore(nix): re-export bundlers we're using by @dpc in https://github.com/fedimint/fedimint/pull/4374
* chore: use sleep_in_test over sleep in tests by @kernelkind in https://github.com/fedimint/fedimint/pull/4376
* refactor: remove register_with_federation_inner by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4377
* test: gateway short channel id assignments by @okjodom in https://github.com/fedimint/fedimint/pull/4275
* chore: split latency test into 5 sub-tests to run in parallel by @dpc in https://github.com/fedimint/fedimint/pull/4390
* chore(backward-compat-test): test each version of every component once  by @dpc in https://github.com/fedimint/fedimint/pull/4389
* chore(devimint): print out stderr of commands we're running by @dpc in https://github.com/fedimint/fedimint/pull/4391
* chore: switch to signing bundled binaries by @dpc in https://github.com/fedimint/fedimint/pull/4372
* fix: slow client recovery in tests by @dpc in https://github.com/fedimint/fedimint/pull/4392
* fix(mint-client): reissuing eternal notes doesn't block by @elsirion in https://github.com/fedimint/fedimint/pull/4384
* chore: ignore uncommitted transaction during db migrations by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4394
* feat: generate essential num guardians InviteCode by @kernelkind in https://github.com/fedimint/fedimint/pull/4371
* fix: run real fedimint-ln-gateway tests by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4388
* chore(deps): bump codecov/codecov-action from 3 to 4 by @dependabot in https://github.com/fedimint/fedimint/pull/3189
* Gatewayd migrations by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4327
* chore: prevent hanging connections failing builds by @dpc in https://github.com/fedimint/fedimint/pull/4401
* chore(ci): update install-nix-action nixpkgs channel  by @dpc in https://github.com/fedimint/fedimint/pull/4402
* chore: switch exported bundlers to deterministic ones by @dpc in https://github.com/fedimint/fedimint/pull/4403
* Degraded federations for devimint and rust tests by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4247
* Remove FederationInfo by @joschisan in https://github.com/fedimint/fedimint/pull/4297
* Add semgrep rule for `.elapsed()` by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4369
* feat: replit support by @Kodylow in https://github.com/fedimint/fedimint/pull/4405
* chore: add basic .editorconfig file by @dpc in https://github.com/fedimint/fedimint/pull/4411
* refactor: run backwards-compatibility tests in parallel by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4413
* chore(client): document joining a federation by @elsirion in https://github.com/fedimint/fedimint/pull/4409
* chore: add blank .semgrepignore & fix findings by @kernelkind in https://github.com/fedimint/fedimint/pull/4417
* Parallel backward compat. tests improvements by @dpc in https://github.com/fedimint/fedimint/pull/4418
* chore: cargo update by @maan2003 in https://github.com/fedimint/fedimint/pull/4408
* fix: Handle http errors in wasm test by @benthecarman in https://github.com/fedimint/fedimint/pull/4420
* feat: `unknown` module by @dpc in https://github.com/fedimint/fedimint/pull/4399
* chore: update rust toolchain by @dpc in https://github.com/fedimint/fedimint/pull/4422
* fix: check if in repl before running replit direnv check by @Kodylow in https://github.com/fedimint/fedimint/pull/4423
* chore: remove unneeded usage of `pub` throughout gateway code by @tvolk131 in https://github.com/fedimint/fedimint/pull/4357
* feat: allow multiple devimint clients with the same name by @maan2003 in https://github.com/fedimint/fedimint/pull/4193
* fix: wrong rust-analyzer version used by @dpc in https://github.com/fedimint/fedimint/pull/4428
* feat: remove gateway from federation by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4366
* chore: add full matrix option to back-compat by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4425
* fix: flaky test_can_change_routing_fees by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4410
* chore(mint-client): test parallel spends and reissuances by @elsirion in https://github.com/fedimint/fedimint/pull/4407
* fix: make `String`s in meta backwards compatible by @elsirion in https://github.com/fedimint/fedimint/pull/4438
* chore: include binary name in test version string by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4439
* chore: decrease sleep time when registration fails by @kernelkind in https://github.com/fedimint/fedimint/pull/4414
* chore: update setup docs by @Kodylow in https://github.com/fedimint/fedimint/pull/4441
* fix: persist xmpp message archives by @Kodylow in https://github.com/fedimint/fedimint/pull/4442
* Allow downloading guardian config by @elsirion in https://github.com/fedimint/fedimint/pull/4415
* chore: address comments from #4415 by @elsirion in https://github.com/fedimint/fedimint/pull/4451
* chore: allocate client db prefix range for external use by @dpc in https://github.com/fedimint/fedimint/pull/4445
* chore: allow download backup manually for recovery by @maan2003 in https://github.com/fedimint/fedimint/pull/4453
* chore: bump mio by @maan2003 in https://github.com/fedimint/fedimint/pull/4455
* fix: support fees for primary module inputs by @joschisan in https://github.com/fedimint/fedimint/pull/4437
* chore: cap maximum backup size at 128KiB, 32KiB per module by @dpc in https://github.com/fedimint/fedimint/pull/4343
* chore: bump nixpkgs by @maan2003 in https://github.com/fedimint/fedimint/pull/4454
* feat: helper for canceling a future on task group shutdown by @maan2003 in https://github.com/fedimint/fedimint/pull/4457
* chore: set FM_INVITE_CODE in devimint dev-fed by @maan2003 in https://github.com/fedimint/fedimint/pull/4461
* chore: add stalled-download-timeout nix config in CI by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4468
* fix: Client::has_pending_recoveries by @maan2003 in https://github.com/fedimint/fedimint/pull/4462
* fix(ci): stop notifying about failing merge queue builds by @dpc in https://github.com/fedimint/fedimint/pull/4469
* chore: move dev shell target to `./target-nix` by @dpc in https://github.com/fedimint/fedimint/pull/4470
* feat(dev): `just bench-compilation` by @dpc in https://github.com/fedimint/fedimint/pull/4471
* chore(deps): bump async-channel from 1.9.0 to 2.2.0 by @dependabot in https://github.com/fedimint/fedimint/pull/4466
* chore(deps): bump http from 0.2.11 to 1.1.0 by @dependabot in https://github.com/fedimint/fedimint/pull/4464
* chore(deps): bump jsonrpsee-types from 0.21.0 to 0.22.2 by @dependabot in https://github.com/fedimint/fedimint/pull/4465
* fix: Gateway Enforce Routing Fees by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4412
* chore(ci): in PR and MQ, build ci version of containers by @dpc in https://github.com/fedimint/fedimint/pull/4472
* fix(ci): cargo doc rebuilding deps by @dpc in https://github.com/fedimint/fedimint/pull/4475
* chore: update log level for mprocs by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4448
* chore: timeouts on version discovery by @dpc in https://github.com/fedimint/fedimint/pull/4476
* chore: increase cross compile timeout in CI by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4487
* fix: wrong git version hash calculated if source dirty by @dpc in https://github.com/fedimint/fedimint/pull/4483
* fix: stick with done progress in recovery handling by @dpc in https://github.com/fedimint/fedimint/pull/4497
* chore: fix nightly clippy warnings by @dpc in https://github.com/fedimint/fedimint/pull/4499
* fix: wait_for_all_recoveries by @maan2003 in https://github.com/fedimint/fedimint/pull/4496
* fix: decrease api discovery timeouts in dev shell and tests by @dpc in https://github.com/fedimint/fedimint/pull/4503
* refactor(client): remove manual client arc counting  by @dpc in https://github.com/fedimint/fedimint/pull/4484
* chore(deps): bump tempfile from 3.10.0 to 3.10.1 by @dependabot in https://github.com/fedimint/fedimint/pull/4479
* feat: fuzzing by @dpc in https://github.com/fedimint/fedimint/pull/4494
* chore: client shutdown on handle drop incorrect by @dpc in https://github.com/fedimint/fedimint/pull/4482
* chore(bench-compilation): improve output, bench check etc.  by @dpc in https://github.com/fedimint/fedimint/pull/4500
* chore: add method to get recover progress by @maan2003 in https://github.com/fedimint/fedimint/pull/4509
* include wasm-test.sh in test-ci-all (almost) by @dpc in https://github.com/fedimint/fedimint/pull/4474
* fix: api discovery task not being cancellable  by @dpc in https://github.com/fedimint/fedimint/pull/4505
* chore(client): on first start, get api version from half of clients by @dpc in https://github.com/fedimint/fedimint/pull/4504
* feat: Rename federation_id() to calculate_federation_id() by @benthecarman in https://github.com/fedimint/fedimint/pull/4506
* test: get denomination from mint server config by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4515
* fix: modules with empty params are broken by @dpc in https://github.com/fedimint/fedimint/pull/4523
* chore: make `fedimnt-cli module <module>` be positional by @dpc in https://github.com/fedimint/fedimint/pull/4522
* chore(ci): cleanup output and print times in test-ci-all by @dpc in https://github.com/fedimint/fedimint/pull/4526
* refactor: remove ldk node in fedimint-testing by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4521
* chore(deps): bump rocksdb from 0.21.0 to 0.22.0 by @dpc in https://github.com/fedimint/fedimint/pull/4532
* chore(deps): bump softprops/action-gh-release from 1 to 2 by @dependabot in https://github.com/fedimint/fedimint/pull/4530
* fix(bench-compilation): creating tmp file in wrong target by @dpc in https://github.com/fedimint/fedimint/pull/4534
* refactor: move LnFederationApi to fedimint-ln-client by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4537
* chore: make the test-ci-all work harder  by @dpc in https://github.com/fedimint/fedimint/pull/4524
* feat: Remove active gateway by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4427
* chore(deps): bump http-body from 0.4.6 to 1.0.0 by @dependabot in https://github.com/fedimint/fedimint/pull/4540
* chore: workaround too long TMPDIR harder  by @dpc in https://github.com/fedimint/fedimint/pull/4541
* chore: add defaults to `just test-compatibility` by @dpc in https://github.com/fedimint/fedimint/pull/4546
* cleanup: remove invite code from client db by @joschisan in https://github.com/fedimint/fedimint/pull/4326
* chore: add FM prefix to gateway ID env vars by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4547
* chore: update jsonrpsee to 0.22.1 by @dpc in https://github.com/fedimint/fedimint/pull/4549
* chore: add `fedimint-empty` module by @dpc in https://github.com/fedimint/fedimint/pull/4511
* chore(ci): print version prefixes in parallel task joblog as well by @dpc in https://github.com/fedimint/fedimint/pull/4552
* chore: cargo upgrade (backwards compatible) by @maan2003 in https://github.com/fedimint/fedimint/pull/4554
* chore(test-ci-all): lower number of parallel jobs on dev machines by @dpc in https://github.com/fedimint/fedimint/pull/4556
* chore(deps): bump cachix/install-nix-action from 25 to 26 by @dependabot in https://github.com/fedimint/fedimint/pull/4529
* chore: remove ignore for test_gateway_client_pay_unpayable_invoice by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4548
* chore(deps): bump hyper from 0.14.28 to 1.2.0 by @dependabot in https://github.com/fedimint/fedimint/pull/4551
* chore(dev-env): `just devimint-env` by @dpc in https://github.com/fedimint/fedimint/pull/4560
* Port replay protection test by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4550
* chore: get rid of WsAdminClient by @dpc in https://github.com/fedimint/fedimint/pull/4520
* chore: backwards incompatible deps updates (1/n) by @maan2003 in https://github.com/fedimint/fedimint/pull/4557
* Add CONTRIBUTING.md and Contributing Section to README.md by @richarddushime in https://github.com/fedimint/fedimint/pull/4539
* fix: make clang available in fuzz shell by @elsirion in https://github.com/fedimint/fedimint/pull/4565
* Fix CI on master by @elsirion in https://github.com/fedimint/fedimint/pull/4490
* chore: add DoS protection against infinite reader on decoding  by @dpc in https://github.com/fedimint/fedimint/pull/4501
* chore: remove repetitive words by @soonsouth in https://github.com/fedimint/fedimint/pull/4566
* chore(prometheus): prefix with fm_ and add lots of metrics by @dpc in https://github.com/fedimint/fedimint/pull/4544
* feat: manual shutdown of client by @maan2003 in https://github.com/fedimint/fedimint/pull/4492
* Followup - Fix CI on master by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4570
* chore: `meta` module by @dpc in https://github.com/fedimint/fedimint/pull/4513
* chore(deps): bump rcgen from 0.10.0 to 0.12.1 by @dependabot in https://github.com/fedimint/fedimint/pull/4569
* chore: disable flaky ecash_oob_highly_parallel by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4574
* feat: make user code put ClientHandle in Arc  by @maan2003 in https://github.com/fedimint/fedimint/pull/4538
* chore(metrics): add peer networking metrics  by @dpc in https://github.com/fedimint/fedimint/pull/4573
* refactor(metrics): combined and polish existing ln module metrics  by @dpc in https://github.com/fedimint/fedimint/pull/4564
* fix(ci): test-ci-all running `parallel` with `--eta` by @dpc in https://github.com/fedimint/fedimint/pull/4578
* chore(devimint-env): fixes & improvements by @dpc in https://github.com/fedimint/fedimint/pull/4577
* chore(metrics): monitor application start with version and ver-hash by @dpc in https://github.com/fedimint/fedimint/pull/4575
* fix(devimint-env): `set -euo pipefail` missing by @dpc in https://github.com/fedimint/fedimint/pull/4583
* chore(devimint): faster and cleaner start by @dpc in https://github.com/fedimint/fedimint/pull/4581
* chore(fedimint-cli): print locking message  only if lock busy by @dpc in https://github.com/fedimint/fedimint/pull/4582
* chore(fedimint-cli): write json error to stdout by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4563
* feat: federation_id guardian endpoint by @Kodylow in https://github.com/fedimint/fedimint/pull/4576
* chore(latency-tests): reissue more notes by @dpc in https://github.com/fedimint/fedimint/pull/4587
* chore: improve logging by @dpc in https://github.com/fedimint/fedimint/pull/4594
* refactor(consensus): rename `debug` to `debug_fmt` by @dpc in https://github.com/fedimint/fedimint/pull/4593
* feat: allow access to FederationError by @maan2003 in https://github.com/fedimint/fedimint/pull/4604
* fix: add_target_dir_to_path using wrong dir by @dpc in https://github.com/fedimint/fedimint/pull/4598
* chore: silence compilation warnings by @dpc in https://github.com/fedimint/fedimint/pull/4592
* chore: disable deprecation warnings by @dpc in https://github.com/fedimint/fedimint/pull/4589
* chore(devimint): add assert_error function by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4605
* chore: remove async from TaskGroup::spawn by @maan2003 in https://github.com/fedimint/fedimint/pull/4601
* chore(devimint): polling maybe a bit too aggressive by @dpc in https://github.com/fedimint/fedimint/pull/4596
* refactor: Move db.rs into server crates by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4567
* chore: improve error of download config by @maan2003 in https://github.com/fedimint/fedimint/pull/4603
* docs: add section on cachix to dev-env docs by @emilioziniades in https://github.com/fedimint/fedimint/pull/4588
* fix: new clippy lints  by @dpc in https://github.com/fedimint/fedimint/pull/4614
* fix: find&replace mistake by @dpc in https://github.com/fedimint/fedimint/pull/4613
* fix: define nextest `dev` profile by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4612
* chore(client): too chatty by @dpc in https://github.com/fedimint/fedimint/pull/4586
* feat: dev commands to decode and encode notes and invite_code to and from json by @Kodylow in https://github.com/fedimint/fedimint/pull/4473
* feat: Support description hashes for invoices by @benthecarman in https://github.com/fedimint/fedimint/pull/4615
* test: port ecash_backup_can_recover_metadata by @bradleystachurski in https://github.com/fedimint/fedimint/pull/4617
* fix: test_gateway_configuration by @m1sterc001guy in https://github.com/fedimint/fedimint/pull/4571
* feat: Support receiving LN for other users by @benthecarman in https://github.com/fedimint/fedimint/pull/3820
* fix(db): version field migration never completing by @dpc in https://github.com/fedimint/fedimint/pull/4585
* [Backport releases/v0.3] fix: remove Database::ensure_global calls by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4632
* [Backport releases/v0.3] chore: expose the client task group by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4640
* [Backport releases/v0.3] fix: bump devimint dkg timeout by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4644
* [Backport releases/v0.3] chore: debug flaky sends_ecash_out_of_band_cancel test by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4646
* [Backport releases/v0.3] feat: add gateway id in lightning operation meta by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4654
* chore: update consensus version (0.3) by @maan2003 in https://github.com/fedimint/fedimint/pull/4639
* [Backport releases/v0.3] chore: helper TaskGroup::spawn_cancellable by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4655
* chore: bump version to 0.3.0-rc.1 by @maan2003 in https://github.com/fedimint/fedimint/pull/4656
* chore: add version to metrics workspace dep by @elsirion in https://github.com/fedimint/fedimint/pull/4634
* [Backport releases/v0.3] feat: Make claim_funded_incoming_contract public by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4683
* [Backport releases/v0.3] feat: add commands to check gatewayd and gateway-cli versions by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4694
* [Backport releases/v0.3] chore(gatewayd): add clap --version by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4706
* [Backport releases/v0.3] Add missing state machine migration by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4709
* [Backport releases/v0.3] fix: database migrations not run by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4708
* fix: autodetect nix pkgs versions from root Cargo.toml by @dpc in https://github.com/fedimint/fedimint/pull/4666
* [Backport releases/v0.3] feat: allow setting up federation via `fedimint-cli` by @fedimint-backports in https://github.com/fedimint/fedimint/pull/4713
* chore: v0.3.0 release candidate 2 by @elsirion in https://github.com/fedimint/fedimint/pull/4711
* backport: fix(fedimint-server): build module decoder registry from config  by @maan2003 in https://github.com/fedimint/fedimint/pull/4726
* chore: v0.3.0-rc.3 by @maan2003 in https://github.com/fedimint/fedimint/pull/4728

## New Contributors :tada:
* @TonyGiorgio made their first contribution in https://github.com/fedimint/fedimint/pull/3783
* @wqxoxo made their first contribution in https://github.com/fedimint/fedimint/pull/4036
* @kernelkind made their first contribution in https://github.com/fedimint/fedimint/pull/4318
* @richarddushime made their first contribution in https://github.com/fedimint/fedimint/pull/4539
* @soonsouth made their first contribution in https://github.com/fedimint/fedimint/pull/4566
* @emilioziniades made their first contribution in https://github.com/fedimint/fedimint/pull/4588

**Full Changelog**: https://github.com/fedimint/fedimint/compare/v0.2.2...v0.3.0

#  v0.2.2: : Federate all the Things II

This release fixes a lot of bugs, both client authors and federation operators are recommended to upgrade.

## Guardian Upgrade Process
We recommend proceeding as follows:
* Coordinate a time with all guardians
* Everyone shuts down their `fedimintd` service
* Make a backup of the data dir
* Upgrade `fedimintd` to v0.2.2 (how depends on the deployment method)
* Check that the version matches for everyone by running `fedimintd version-hash`
* Everyone starts their `fedimintd` service again

While this is not a consensus upgrade and thus doesn't require coordination we recommend not running different versions of `fedimintd` together since it is not supported and hasn't been tested.

## Highlighted Changes

* [Fix liveness bug in case guardians are offline](https://github.com/fedimint/fedimint/commit/66d7faff1f7b330f0be1455ac0ef8c49a1489da2)
* [chore: speed up recovery by batching and streaming](https://github.com/fedimint/fedimint/commit/ee600152adfb55085ab00576675972186d1a53e2)
* Bumping deps: `h2`, `ahash`, `shlex` due to some CVEs
* More efficient session counting to avoid slowdown of long-running federations #4203
* Fix: client always retries on errors that are not meant to fail operations 8b57b8a1502d95ad931048d16f9ceeb32a4398f7
* [Expose `fedimint-dbtool`](https://github.com/fedimint/fedimint/commit/1a441e11b757f8bdf186cd40224eb6c93cdaabda) for easier debugging
* Switch to a fork of AlephBFT that makes some interfaces async to avoid locking up async executors with sync code 90b7d6c574052f09f97f4abe2d8fb9e9b5b899aa + 4b0f47c514083096778c188f19aeb01adb7e109e
* [Make LN gateway to be used for a payment known upfront to be able to preview fees](https://github.com/fedimint/fedimint/commit/93df3a00c17cd76169ce33f96db0d196fc3cd05e)
* [chore: upgrade tonic_lnd to 0.2.0](https://github.com/fedimint/fedimint/commit/01c7ee6daa8213d0a0429e8436516e897fd67822)
* [fix: log warning on invalid header signature from peer](https://github.com/fedimint/fedimint/commit/85637e84bb9a2ad119c0a91e6280f74225e3b97c)
* [feat: expose pending accepted consensus items in endpoint for easier debugging](https://github.com/fedimint/fedimint/commit/6a81b5f174e716af57c78fca28e4ab093ce498d1) + #4180

For the complete set of changes see https://github.com/fedimint/fedimint/commits/v0.2.2/


# v0.2.1: Federate all the Things

This is the first version that will stay compatible for a long time and provide an upgrade path into the indefinite future.

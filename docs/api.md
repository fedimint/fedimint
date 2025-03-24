# Fedimint Server API Endpoints

This lists and documents all API endpoints available in the Fedimint server.

<!-- Update this document with `just ai-generate-api-docs` -->
Note that it is currently AI-generated, and best effort, so should be taken
with a grain of salt.

Backward compatibility of the DKG API (setup process) is currently not guaranteed.

APIs of the other core server APIs and modules is internally versioned and
backward compatible for the purpose of consumption by fedimint clients.

Use [github search to find more details about every API](https://github.com/search?q=repo%3Afedimint%2Ffedimint+api_endpoint%21&type=code).

## Core Server API Endpoints

### Version Endpoint
- **Endpoint**: `version`
- **Arguments**: None
- **Returns**: [`SupportedApiVersionsSummary`](https://docs.fedimint.org/?search=SupportedApiVersionsSummary)
- **Purpose**: Returns the API versions supported by the server.

### Submit Transaction Endpoint
- **Endpoint**: `submit_transaction`
- **Arguments**: [`SerdeTransaction`](https://docs.fedimint.org/?search=SerdeTransaction) - A serialized transaction
- **Returns**: [`TransactionSubmissionOutcome`](https://docs.fedimint.org/?search=TransactionSubmissionOutcome)
- **Purpose**: Submits a transaction to the federation for processing.

### Await Transaction Endpoint
- **Endpoint**: `await_transaction`
- **Arguments**: [`TransactionId`](https://docs.fedimint.org/?search=TransactionId) - The hash of a transaction
- **Returns**: [`TransactionId`](https://docs.fedimint.org/?search=TransactionId)
- **Purpose**: Waits for a transaction to be processed and returns when it's complete.

### Await Output Outcome Endpoint (Deprecated)
- **Endpoint**: `await_output_outcome`
- **Arguments**: [`OutPoint`](https://docs.fedimint.org/?search=OutPoint) - A transaction output reference
- **Returns**: [`DynOutputOutcome`](https://docs.fedimint.org/?search=DynOutputOutcome)
- **Purpose**: Waits for and returns the outcome of a specific transaction output.

### Invite Code Endpoint
- **Endpoint**: `invite_code`
- **Arguments**: None
- **Returns**: `String`
- **Purpose**: Returns the federation invite code.

### Federation ID Endpoint
- **Endpoint**: `federation_id`
- **Arguments**: None
- **Returns**: `String`
- **Purpose**: Returns the unique identifier for the federation.

### Client Config Endpoint
- **Endpoint**: `client_config`
- **Arguments**: None
- **Returns**: [`ClientConfig`](https://docs.fedimint.org/?search=ClientConfig)
- **Purpose**: Returns the client configuration for connecting to the federation.

### Client Config JSON Endpoint
- **Endpoint**: `client_config_json`
- **Arguments**: None
- **Returns**: [`JsonClientConfig`](https://docs.fedimint.org/?search=JsonClientConfig)
- **Purpose**: Returns the client configuration in JSON format (helper for Admin UI).

### Server Config Consensus Hash Endpoint
- **Endpoint**: `server_config_consensus_hash`
- **Arguments**: None
- **Returns**: [`sha256::Hash`](https://docs.fedimint.org/?search=sha256::Hash)
- **Purpose**: Returns the hash of the consensus configuration.

### Setup Status Endpoint
- **Endpoint**: `setup_status`
- **Arguments**: None
- **Returns**: [`SetupStatus`](https://docs.fedimint.org/?search=SetupStatus)
- **Purpose**: Returns the current setup status of the federation.

### Consensus Ord Latency Endpoint
- **Endpoint**: `consensus_ord_latency`
- **Arguments**: None
- **Returns**: `Option<Duration>`
- **Purpose**: Returns the current consensus ordering latency if available.

### P2P Connection Status Endpoint
- **Endpoint**: `p2p_connection_status`
- **Arguments**: None
- **Returns**: `BTreeMap<PeerId, Option<Duration>>`
- **Purpose**: Returns the connection status to other peers in the federation.

### Session Count Endpoint
- **Endpoint**: `session_count`
- **Arguments**: None
- **Returns**: `u64`
- **Purpose**: Returns the number of completed consensus sessions.

### Await Session Outcome Endpoint
- **Endpoint**: `await_session_outcome`
- **Arguments**: `u64` - Session index
- **Returns**: [`SessionOutcome`](https://docs.fedimint.org/?search=SessionOutcome)
- **Purpose**: Waits for and returns the outcome of a specific consensus session.

### Await Signed Session Outcome Endpoint
- **Endpoint**: `await_signed_session_outcome`
- **Arguments**: `u64` - Session index
- **Returns**: [`SignedSessionOutcome`](https://docs.fedimint.org/?search=SignedSessionOutcome)
- **Purpose**: Waits for and returns the signed outcome of a specific consensus session.

### Session Status Endpoint
- **Endpoint**: `session_status`
- **Arguments**: `u64` - Session index
- **Returns**: [`SessionStatus`](https://docs.fedimint.org/?search=SessionStatus)
- **Purpose**: Returns the current status of a specific consensus session.

### Session Status V2 Endpoint
- **Endpoint**: `signed_session_status`
- **Arguments**: `u64` - Session index
- **Returns**: [`SessionStatusV2`](https://docs.fedimint.org/?search=SessionStatusV2)
- **Purpose**: Returns the current status of a specific consensus session with enhanced information.

### Shutdown Endpoint
- **Endpoint**: `shutdown`
- **Arguments**: `Option<u64>` - Optional session index to wait for before shutdown
- **Returns**: None
- **Purpose**: Initiates a shutdown of the federation server.

### Audit Endpoint
- **Endpoint**: `audit`
- **Arguments**: None (requires authentication)
- **Returns**: [`AuditSummary`](https://docs.fedimint.org/?search=AuditSummary)
- **Purpose**: Returns an audit summary of the federation's state.

### Guardian Config Backup Endpoint
- **Endpoint**: `download_guardian_backup`
- **Arguments**: None (requires authentication)
- **Returns**: [`GuardianConfigBackup`](https://docs.fedimint.org/?search=GuardianConfigBackup)
- **Purpose**: Returns an encrypted backup of the guardian's configuration.

### Backup Endpoint
- **Endpoint**: `backup`
- **Arguments**: [`SignedBackupRequest`](https://docs.fedimint.org/?search=SignedBackupRequest)
- **Returns**: None
- **Purpose**: Stores a client backup in the federation.

### Recover Endpoint
- **Endpoint**: `recover`
- **Arguments**: [`PublicKey`](https://docs.fedimint.org/?search=PublicKey) - Client's public key
- **Returns**: `Option<`[`ClientBackupSnapshot`](https://docs.fedimint.org/?search=ClientBackupSnapshot)`>`
- **Purpose**: Retrieves a client's backup if available.

### Auth Endpoint
- **Endpoint**: `auth`
- **Arguments**: None (requires authentication)
- **Returns**: None
- **Purpose**: Tests if the provided authentication is valid.

### API Announcements Endpoint
- **Endpoint**: `api_announcements`
- **Arguments**: None
- **Returns**: `BTreeMap<`[`PeerId`](https://docs.fedimint.org/?search=PeerId)`, `[`SignedApiAnnouncement`](https://docs.fedimint.org/?search=SignedApiAnnouncement)`>`
- **Purpose**: Returns the API URL announcements from all peers.

### Submit API Announcement Endpoint
- **Endpoint**: `submit_api_announcement`
- **Arguments**: [`SignedApiAnnouncementSubmission`](https://docs.fedimint.org/?search=SignedApiAnnouncementSubmission)
- **Returns**: None
- **Purpose**: Submits an API URL announcement for a peer.

### Sign API Announcement Endpoint
- **Endpoint**: `sign_api_announcement`
- **Arguments**: [`SafeUrl`](https://docs.fedimint.org/?search=SafeUrl) - New API URL
- **Returns**: [`SignedApiAnnouncement`](https://docs.fedimint.org/?search=SignedApiAnnouncement)
- **Purpose**: Signs and stores a new API URL announcement for this guardian.

### Fedimintd Version Endpoint
- **Endpoint**: `fedimintd_version`
- **Arguments**: None
- **Returns**: `String`
- **Purpose**: Returns the version of the fedimintd server.

### Backup Statistics Endpoint
- **Endpoint**: `backup_statistics`
- **Arguments**: None (requires authentication)
- **Returns**: [`BackupStatistics`](https://docs.fedimint.org/?search=BackupStatistics)
- **Purpose**: Returns statistics about client backups stored in the federation.

## Meta Module API Endpoints

### Submit Meta Value Endpoint
- **Endpoint**: `submit`
- **Arguments**: [`SubmitRequest`](https://docs.fedimint.org/?search=SubmitRequest) - Contains key and value to submit (requires authentication)
- **Returns**: None
- **Purpose**: Submits a value for a specific key to be considered for consensus.

### Get Consensus Endpoint
- **Endpoint**: `get_consensus`
- **Arguments**: [`GetConsensusRequest`](https://docs.fedimint.org/?search=GetConsensusRequest) - Contains the key to query
- **Returns**: `Option<`[`MetaConsensusValue`](https://docs.fedimint.org/?search=MetaConsensusValue)`>` - The consensus value if it exists
- **Purpose**: Retrieves the current consensus value for a specific key.

### Get Consensus Revision Endpoint
- **Endpoint**: `get_consensus_rev`
- **Arguments**: [`GetConsensusRequest`](https://docs.fedimint.org/?search=GetConsensusRequest) - Contains the key to query
- **Returns**: `Option<u64>` - The revision number if the key exists
- **Purpose**: Retrieves the current revision number for a consensus key.

### Get Submissions Endpoint
- **Endpoint**: `get_submissions`
- **Arguments**: [`GetSubmissionsRequest`](https://docs.fedimint.org/?search=GetSubmissionsRequest) - Contains the key to query (requires authentication)
- **Returns**: `BTreeMap<`[`PeerId`](https://docs.fedimint.org/?search=PeerId)`, `[`MetaValue`](https://docs.fedimint.org/?search=MetaValue)`>` - Map of peer IDs to their submitted values
- **Purpose**: Retrieves all current submissions for a specific key from all peers.

## Mint Module API Endpoints

### Note Spent Endpoint
- **Endpoint**: `note_spent`
- **Arguments**: [`Nonce`](https://docs.fedimint.org/?search=Nonce) - The nonce of the note to check
- **Returns**: `bool` - Whether the note has been spent
- **Purpose**: Checks if a specific e-cash note has been spent.

### Blind Nonce Used Endpoint
- **Endpoint**: `blind_nonce_used`
- **Arguments**: [`BlindNonce`](https://docs.fedimint.org/?search=BlindNonce) - The blind nonce to check
- **Returns**: `bool` - Whether the blind nonce has been used
- **Purpose**: Checks if a specific blind nonce has already been used in the federation.

## Wallet Module API Endpoints

### Block Count Endpoint
- **Endpoint**: `block_count`
- **Arguments**: None
- **Returns**: `u32` - The current consensus block count
- **Purpose**: Returns the current block count agreed upon by consensus.

### Block Count Local Endpoint
- **Endpoint**: `block_count_local`
- **Arguments**: None
- **Returns**: `Option<u32>` - The local block count if available
- **Purpose**: Returns the local node's current block count.

### Peg Out Fees Endpoint
- **Endpoint**: `peg_out_fees`
- **Arguments**: `(`[`Address<NetworkUnchecked>`](https://docs.fedimint.org/?search=Address<NetworkUnchecked>)`, u64)` - Destination address and amount in sats
- **Returns**: `Option<`[`PegOutFees`](https://docs.fedimint.org/?search=PegOutFees)`>` - Fee information if calculable
- **Purpose**: Calculates the fees required for a peg-out transaction.

### Bitcoin Kind Endpoint
- **Endpoint**: `bitcoin_kind`
- **Arguments**: None
- **Returns**: `String` - The type of Bitcoin node connection
- **Purpose**: Returns the type of Bitcoin node the federation is connected to.

### Bitcoin RPC Config Endpoint
- **Endpoint**: `bitcoin_rpc_config`
- **Arguments**: None (requires authentication)
- **Returns**: [`BitcoinRpcConfig`](https://docs.fedimint.org/?search=BitcoinRpcConfig) - Bitcoin RPC configuration
- **Purpose**: Returns the Bitcoin RPC configuration used by the federation.

### Wallet Summary Endpoint
- **Endpoint**: `wallet_summary`
- **Arguments**: None
- **Returns**: [`WalletSummary`](https://docs.fedimint.org/?search=WalletSummary) - Summary of the wallet state
- **Purpose**: Returns a summary of the wallet's current state including UTXOs and transactions.

### Module Consensus Version Endpoint
- **Endpoint**: `module_consensus_version`
- **Arguments**: None
- **Returns**: [`ModuleConsensusVersion`](https://docs.fedimint.org/?search=ModuleConsensusVersion) - Current consensus version
- **Purpose**: Returns the current consensus version of the wallet module.

### Supported Module Consensus Version Endpoint
- **Endpoint**: `supported_module_consensus_version`
- **Arguments**: None
- **Returns**: [`ModuleConsensusVersion`](https://docs.fedimint.org/?search=ModuleConsensusVersion) - Maximum supported version
- **Purpose**: Returns the maximum supported consensus version of the wallet module.

### Activate Consensus Version Voting Endpoint
- **Endpoint**: `activate_consensus_version_voting`
- **Arguments**: None (requires authentication)
- **Returns**: None
- **Purpose**: Activates voting for a new consensus version.

### UTXO Confirmed Endpoint
- **Endpoint**: `utxo_confirmed`
- **Arguments**: [`bitcoin::OutPoint`](https://docs.fedimint.org/?search=bitcoin::OutPoint) - The outpoint to check
- **Returns**: `bool` - Whether the UTXO is confirmed
- **Purpose**: Checks if a specific UTXO is confirmed in the Bitcoin blockchain.

## Lightning (LNv2) Module API Endpoints

### Consensus Block Count Endpoint
- **Endpoint**: `consensus_block_count`
- **Arguments**: None
- **Returns**: `u64` - Current consensus block count
- **Purpose**: Returns the current Bitcoin block count agreed upon by consensus.

### Await Incoming Contract Endpoint
- **Endpoint**: `await_incoming_contract`
- **Arguments**: `(`[`ContractId`](https://docs.fedimint.org/?search=ContractId)`, u64)` - Contract ID and expiration time
- **Returns**: `Option<`[`ContractId`](https://docs.fedimint.org/?search=ContractId)`>` - Contract ID if found before expiration
- **Purpose**: Waits for an incoming Lightning contract to be available or until expiration.

### Await Preimage Endpoint
- **Endpoint**: `await_preimage`
- **Arguments**: `(`[`ContractId`](https://docs.fedimint.org/?search=ContractId)`, u64)` - Contract ID and expiration time
- **Returns**: `Option<[u8; 32]>` - Preimage if found before expiration
- **Purpose**: Waits for a payment preimage to be revealed or until expiration.

### Decryption Key Share Endpoint
- **Endpoint**: `decryption_key_share`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - The contract ID
- **Returns**: [`DecryptionKeyShare`](https://docs.fedimint.org/?search=DecryptionKeyShare) - The decryption key share
- **Purpose**: Returns the guardian's decryption key share for a specific contract.

### Outgoing Contract Expiration Endpoint
- **Endpoint**: `outgoing_contract_expiration`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - The contract ID
- **Returns**: `Option<u64>` - Blocks until expiration if contract exists
- **Purpose**: Returns the number of blocks until an outgoing contract expires.

### Add Gateway Endpoint
- **Endpoint**: `add_gateway`
- **Arguments**: [`SafeUrl`](https://docs.fedimint.org/?search=SafeUrl) - Gateway URL (requires authentication)
- **Returns**: `bool` - Whether the gateway was newly added
- **Purpose**: Adds a Lightning gateway to the federation's list.

### Remove Gateway Endpoint
- **Endpoint**: `remove_gateway`
- **Arguments**: [`SafeUrl`](https://docs.fedimint.org/?search=SafeUrl) - Gateway URL (requires authentication)
- **Returns**: `bool` - Whether the gateway was removed
- **Purpose**: Removes a Lightning gateway from the federation's list.

### Gateways Endpoint
- **Endpoint**: `gateways`
- **Arguments**: None
- **Returns**: `Vec<`[`SafeUrl`](https://docs.fedimint.org/?search=SafeUrl)`>` - List of registered gateways
- **Purpose**: Returns the list of Lightning gateways registered with the federation.

## Lightning (LN) Module API Endpoints

### Block Count Endpoint
- **Endpoint**: `block_count`
- **Arguments**: None
- **Returns**: `Option<u64>` - Current consensus block count
- **Purpose**: Returns the current Bitcoin block count agreed upon by consensus.

### Account Endpoint
- **Endpoint**: `account`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - Contract ID to query
- **Returns**: `Option<`[`ContractAccount`](https://docs.fedimint.org/?search=ContractAccount)`>` - Contract account information if found
- **Purpose**: Returns information about a specific Lightning contract account.

### Await Account Endpoint
- **Endpoint**: `await_account`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - Contract ID to wait for
- **Returns**: [`ContractAccount`](https://docs.fedimint.org/?search=ContractAccount) - Contract account information
- **Purpose**: Waits for a Lightning contract account to be available and returns it.

### Await Block Height Endpoint
- **Endpoint**: `await_block_height`
- **Arguments**: `u64` - Block height to wait for
- **Returns**: None
- **Purpose**: Waits until the consensus block height reaches the specified value.

### Await Outgoing Contract Cancelled Endpoint
- **Endpoint**: `await_outgoing_contract_cancelled`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - Contract ID to wait for
- **Returns**: [`ContractAccount`](https://docs.fedimint.org/?search=ContractAccount) - Contract account information
- **Purpose**: Waits for an outgoing contract to be cancelled and returns its account information.

### Get Decrypted Preimage Status Endpoint
- **Endpoint**: `get_decrypted_preimage_status`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - Contract ID to query
- **Returns**: `(`[`IncomingContractAccount`](https://docs.fedimint.org/?search=IncomingContractAccount)`, `[`DecryptedPreimageStatus`](https://docs.fedimint.org/?search=DecryptedPreimageStatus)`)` - Account and preimage status
- **Purpose**: Returns the status of a decrypted preimage for a specific contract.

### Await Preimage Decryption Endpoint
- **Endpoint**: `await_preimage_decryption`
- **Arguments**: [`ContractId`](https://docs.fedimint.org/?search=ContractId) - Contract ID to wait for
- **Returns**: `(`[`IncomingContractAccount`](https://docs.fedimint.org/?search=IncomingContractAccount)`, Option<`[`Preimage`](https://docs.fedimint.org/?search=Preimage)`>)` - Account and preimage if available
- **Purpose**: Waits for a preimage to be decrypted and returns it along with the contract account.

### Offer Endpoint
- **Endpoint**: `offer`
- **Arguments**: [`bitcoin_hashes::sha256::Hash`](https://docs.fedimint.org/?search=bitcoin_hashes::sha256::Hash) - Payment hash to query
- **Returns**: `Option<`[`IncomingContractOffer`](https://docs.fedimint.org/?search=IncomingContractOffer)`>` - Offer information if found
- **Purpose**: Returns information about a specific incoming contract offer.

### Await Offer Endpoint
- **Endpoint**: `await_offer`
- **Arguments**: [`bitcoin_hashes::sha256::Hash`](https://docs.fedimint.org/?search=bitcoin_hashes::sha256::Hash) - Payment hash to wait for
- **Returns**: [`IncomingContractOffer`](https://docs.fedimint.org/?search=IncomingContractOffer) - Offer information
- **Purpose**: Waits for an incoming contract offer to be available and returns it.

### List Gateways Endpoint
- **Endpoint**: `list_gateways`
- **Arguments**: None
- **Returns**: `Vec<`[`LightningGatewayAnnouncement`](https://docs.fedimint.org/?search=LightningGatewayAnnouncement)`>` - List of registered gateways
- **Purpose**: Returns the list of Lightning gateways registered with the federation.

### Register Gateway Endpoint
- **Endpoint**: `register_gateway`
- **Arguments**: [`LightningGatewayAnnouncement`](https://docs.fedimint.org/?search=LightningGatewayAnnouncement) - Gateway information
- **Returns**: None
- **Purpose**: Registers a Lightning gateway with the federation.

### Remove Gateway Challenge Endpoint
- **Endpoint**: `remove_gateway_challenge`
- **Arguments**: [`PublicKey`](https://docs.fedimint.org/?search=PublicKey) - Gateway ID
- **Returns**: `Option<`[`sha256::Hash`](https://docs.fedimint.org/?search=sha256::Hash)`>` - Challenge hash if gateway exists
- **Purpose**: Returns a challenge that must be signed to remove a gateway.

### Remove Gateway Endpoint
- **Endpoint**: `remove_gateway`
- **Arguments**: [`RemoveGatewayRequest`](https://docs.fedimint.org/?search=RemoveGatewayRequest) - Request with gateway ID and signatures
- **Returns**: `bool` - Whether the gateway was successfully removed
- **Purpose**: Removes a Lightning gateway from the federation's list.

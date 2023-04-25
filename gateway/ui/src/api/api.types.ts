import { Federation } from '../federation.types';

// Mintgate is an API to interact with the Gateway server
export interface Mintgate {
	fetchInfo: () => Promise<GatewayInfo>;
	fetchAddress: () => Promise<string>;
	connectFederation: (connectInfo: string) => Promise<Federation>;
	/**
	 * Complete a deposit to a federation served by the Gateway
	 * @param federationId id of the federation to deposit to
	 * @param txOutProof transaction out proof for the deposit made to address previously sourced from federation via fetchAddress
	 * @param tx transaction hash for the deposit made to address previously sourced from federation via fetchAddress
	 * @returns `TransactionId` from the Fedimint federation
	 */
	completeDeposit: (
		federationId: string,
		txOutProof: string,
		tx: string
	) => Promise<string>;

	/**
	 *  Request a withdrawal from a fedration served by the Gateway
	 * @param federationId  id of the federation to withdraw from
	 * @param amountSat the amount in satoshis to be withdrawn from the federation
	 * @param address the bitcoin address to withdraw to
	 * @returns `TransactionId` from the Fedimint federation
	 */
	requestWithdrawal: (
		federationId: string,
		amountSat: number,
		address: string
	) => Promise<string>;
}

// GatewayInfo is the information returned by the Gateway server
export interface GatewayInfo {
	version_hash: string;
	federations: Federation[];
}

/** TransactionId of a fedimint federation */
export type TransactionId = string;

export interface Explorer {
	// Try get transaction status for a tx with given address
	watchAddressForTransaction: (
		address: string
	) => Promise<TransactionStatus | null>;

	// Try get transaction status for a tx with given address and transaction id.
	// Since we know the transaction id, this should be more efficient than watchAddressForTransaction
	watchTransactionStatus: (
		address: string,
		txid: string
	) => Promise<TransactionStatus>;

	// Try get transaction proof for a tx with given transaction id
	fetchTransactionProof: (txid: string) => Promise<TransactionProof>;

	// Fetch the block height at current chain tip
	fetchLatestBlockHeight: () => Promise<number>;
}

export interface TransactionStatus {
	/** transaction id */
	transactionId: string;
	/** amount detected in transaction */
	amount_btc: number;
	/** number of confirmations */
	confirmations: number;
	/** status of the transaction */
	status: 'pending' | 'confirmed';
	/** Url to view this transaction on the explorer where status information was sourced */
	viewTransactionUrl: string;
}

export interface TransactionProof {
	/** Merkle proof of transaction */
	transactionOutProof: string;
	/** Sha256 hash of transaction */
	transactionHash: string;
}

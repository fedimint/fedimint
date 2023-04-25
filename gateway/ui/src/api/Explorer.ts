import { Explorer, TransactionStatus, TransactionProof } from './api.types';

interface ChaintipCache {
	// block height at current chain tip
	chaintip: number;
	// timestamp when the chaintip was fetched
	fetched: number;
}

export class BlockstreamExplorer implements Explorer {
	// Base url for the blockstream explorer
	public baseUrl: string;
	chaintip: ChaintipCache | undefined;

	constructor(baseUrl: string) {
		this.baseUrl = baseUrl;
	}

	watchAddressForTransaction = async (
		address: string
	): Promise<TransactionStatus> => {
		try {
			const res: Response = await fetch(
				`${this.baseUrl}/address/${address}/txs/mempool`
			);

			if (res.ok) {
				const txns = await res.json();

				if (txns.length === 0) {
					return Promise.reject('No transaction found in the mempool');
				}

				let txout: { value: number } | undefined;

				const tx = txns.find((tx: any) => {
					txout = tx.vout.find((out: any) => {
						return out.scriptpubkey_address === address;
					});
					return txout !== undefined;
				});

				if (!tx || !txout) {
					return Promise.reject('No transaction found to our address');
				}

				return Promise.resolve({
					transactionId: tx.txid,
					amount_btc: txout.value / 100000000,
					confirmations: 0,
					status: 'pending',
					viewTransactionUrl: `${this.baseUrl.replace('/api/', '/')}tx/${
						tx.txid
					}`,
				});
			}

			throw new Error('Error fetching transaction');
		} catch (err) {
			return Promise.reject(err);
		}
	};

	watchTransactionStatus = async (
		address: string,
		txid: string
	): Promise<TransactionStatus> => {
		try {
			const res: Response = await fetch(`${this.baseUrl}/tx/${txid}`);

			if (res.ok) {
				const tx = await res.json();

				const txout = tx.vout.find((out: any) => {
					return out.scriptpubkey_address === address;
				});

				if (!txout) {
					return Promise.reject('No transaction found to our address');
				}

				const chaintip = await this.fetchLatestBlockHeight();
				const height =
					tx.status.block_height !== undefined
						? Number(tx.status.block_height)
						: chaintip;

				return Promise.resolve({
					transactionId: tx.txid,
					amount_btc: txout.value / 100000000,
					confirmations: chaintip - height,
					status: tx.status.confirmed ? 'confirmed' : 'pending',
					viewTransactionUrl: `${this.baseUrl.replace('/api/', '/')}tx/${
						tx.txid
					}`,
				});
			}

			throw new Error('Error fetching transaction');
		} catch (err) {
			return Promise.reject(err);
		}
	};

	fetchTransactionProof = async (txid: string): Promise<TransactionProof> => {
		try {
			const proofres: Response = await fetch(
				`${this.baseUrl}/tx/${txid}/merkleblock-proof`
			);
			const proof = proofres.ok && (await proofres.text());

			const hashres: Response = await fetch(`${this.baseUrl}/tx/${txid}/hex`);
			const hash = hashres.ok && (await hashres.text());

			if (!proof || !hash) {
				throw new Error('Error fetching transaction proof');
			}

			return Promise.resolve({
				transactionOutProof: proof,
				transactionHash: hash,
			});
		} catch (err) {
			return Promise.reject(err);
		}
	};

	fetchLatestBlockHeight = async (): Promise<number> => {
		const time = Date.now();

		// if we have a cached chaintip and it's less than 10 minutes old, return it
		// this approximates the latest block height, but can be slightly off
		if (this.chaintip !== undefined && time - this.chaintip.fetched <= 600000) {
			console.log('Using cached chaintip', this.chaintip.chaintip);
			return Promise.resolve(this.chaintip.chaintip);
		}

		try {
			const res: Response = await fetch(`${this.baseUrl}/blocks/tip/height`);

			if (res.ok) {
				const height = await res.json();

				// cache the latest chain tip
				this.chaintip = { chaintip: Number(height), fetched: time };

				return Promise.resolve(this.chaintip.chaintip);
			}

			throw new Error('Error fetching latest block height');
		} catch (err) {
			return Promise.reject(err);
		}
	};
}

import { GatewayInfo, Mintgate } from './api.types';
import { Federation } from '../federation.types';

// NullGatewayInfo is a placeholder for when the GatewayInfo is not yet loaded
export const NullGatewayInfo: GatewayInfo = {
	version_hash: '',
	federations: [],
};

// MockMintgate is a mock implementation of the Mintgate API
export class MockMintgate implements Mintgate {
	fetchInfo = async (): Promise<GatewayInfo> => {
		return {
			federations: [
				{
					federation_id: 'Hals_trusty_mint',
					mint_pubkey:
						'4222d0e6f9f4e0a9d471c81b3ee454032cddc8590a9aebf43332bb2d3ecb976c',
					details: {
						description: 'Hals Trusty Mint',
						date_created: '2018-01-01T00:00:00Z',
						name: 'Hals_trusty_mint',
						active: true,
					},
				},

				{
					federation_id: 'FTX_yield_gen',
					mint_pubkey:
						'c679bce3d2bb23334fbea9a0958cddc230454ee3b18c174d9a0e4f9f6e0d2224',
					details: {
						description: 'FTX yield generator',
						date_created: '2019-01-01T00:00:00Z',
						name: 'FTX_yield_gen',
						active: true,
					},
				},

				{
					federation_id: 'Qala_devs',
					mint_pubkey:
						'1d2eb31bb4c307b466e1a7c910693bc5754799ec705b14f760e74d5d4968acf9',
					details: {
						description: 'Qala_devs stacking sats',
						date_created: '2020-01-01T00:00:00Z',
						name: 'Qala_devs',
						active: false,
					},
				},
			],
			version_hash: 'f876d12a78df7d4ef5b3a4913590ded6bfe5c3b1',
		};
	};

	fetchAddress = async (_federationId: string): Promise<string> => {
		// Use IP's bitcoin address as a mock
		return 'bc1qgf60crqtlxn7279tgh8lsxzagmu97cyuwtykxwv026s9hwg427fsjvw7uz';
	};

	connectFederation = async (_connectInfo: string): Promise<Federation> => {
		// TODO: autogenerate mock names
		const federation_id = 'mock_federation';
		// TODO: autogenerate mock pubkeys
		const mint_pubkey =
			'4222d0e6f9f4e0a9d471c81b3ee454032cddc8590a9aebf43332bb2d3ecb976c';

		return Promise.resolve({
			federation_id,
			mint_pubkey,
			details: {
				description: 'Newly connected federation mock',
				date_created: Date.now().toString(),
				name: 'mock_federation',
				url: '',
				active: true,
			},
		});
	};

	completeDeposit = async (
		_federationId: string,
		_txOutProof: string,
		_tx: string
	): Promise<string> => {
		return Promise.resolve('mock_txid');
	};

	requestWithdrawal = async (
		_federationId: string,
		_amountSat: number,
		_address: string
	): Promise<string> => {
		return Promise.resolve(
			'de3d5bf1e3c1b3be2a1e025825f751629390ad60c8f91723e330f2356d99c59b'
		);
	};
}

// RealMintgate makes API calls to a given Mintgate API
export class RealMintgate implements Mintgate {
	private readonly password: string;

	constructor(private readonly baseUrl: string) {
		this.password = process.env.REACT_APP_FM_GATEWAY_API_PASSWORD || '';
	}

	fetchInfo = async (): Promise<GatewayInfo> => {
		try {
			const res: Response = await fetch(`${this.baseUrl}/info`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.password}`,
				},
				body: JSON.stringify({}),
			});

			if (res.ok) {
				const info: GatewayInfo = await res.json();
				return Promise.resolve(info);
			}

			throw new Error(
				`Error fetching gateway info\nStatus : ${res.status}\nReason : ${res.statusText}\n`
			);
		} catch (err) {
			return Promise.reject(err);
		}
	};

	fetchAddress = async (federationId: string): Promise<string> => {
		try {
			const res: Response = await fetch(`${this.baseUrl}/address`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.password}`,
				},
				body: JSON.stringify({
					federation_id: federationId,
				}),
			});

			if (res.ok) {
				const address: string = (await res.json()).address;
				return Promise.resolve(address);
			}

			throw new Error(
				`Error fetching federation address\nStatus : ${res.status}\nReason : ${res.statusText}\n`
			);
		} catch (err) {
			return Promise.reject(err);
		}
	};

	connectFederation = async (_connectInfo: string): Promise<Federation> => {
		try {
			throw new Error('Not implemented');
		} catch (err) {
			return Promise.reject(err);
		}
	};

	completeDeposit = async (
		_federationId: string,
		_txOutProof: string,
		_tx: string
	): Promise<string> => {
		try {
			throw new Error('Not implemented');
		} catch (err) {
			return Promise.reject(err);
		}
	};

	requestWithdrawal = async (
		_federationId: string,
		_amountSat: number,
		_address: string
	): Promise<string> => {
		try {
			throw new Error('Not implemented');
		} catch (err) {
			return Promise.reject(err);
		}
	};
}

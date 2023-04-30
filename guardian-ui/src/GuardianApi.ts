import { JsonRpcError, JsonRpcWebsocket } from 'jsonrpc-client-websocket';

export interface ApiInterface {
	setPassword: (password: string) => Promise<void>;
	setConnections: (ourName: string, leaderUrl?: string) => Promise<void>;
	getDefaults: () => Promise<unknown>;
	getStatus: () => Promise<string>;
	getConsensusParams: () => Promise<unknown>;
	getVerifyConfigHash: () => Promise<string>;
	awaitPeers: (numPeers: number) => Promise<void>;
	runDkg: () => Promise<void>;
	verifyConfigs: (configHashes: string[]) => Promise<void>;
	startConsensus: () => Promise<void>;
	shutdown: () => Promise<boolean>;
}

export class GuardianApi implements ApiInterface {
	password: string | null;
	websocket: JsonRpcWebsocket | null;

	constructor() {
		this.password = null;
		this.websocket = null;

		this.connect();
	}

	private connect = async (): Promise<JsonRpcWebsocket> => {
		if (this.websocket !== null) {
			return this.websocket;
		}

		const websocketUrl = process.env.REACT_APP_FM_CONFIG_API;

		if (!websocketUrl) {
			throw new Error('REACT_APP_FM_CONFIG_API not set');
		}

		const requestTimeoutMs = 20000;
		const websocket = new JsonRpcWebsocket(
			websocketUrl,
			requestTimeoutMs,
			(error: JsonRpcError) => {
				console.error('failed to create websocket', error);
				this.shutdown();
			}
		);
		await websocket.open();

		this.websocket = websocket;
		return Promise.resolve(this.websocket);
	};

	private rpc = async <T>(method: string, params: unknown): Promise<T> => {
		try {
			const websocket = await this.connect();

			const response = await websocket.call(method, [
				{
					auth: this.password,
					params,
				},
			]);

			return response.result as T;
		} catch (error) {
			console.error('websocket rpc error', error);
			throw error;
		}
	};

	shutdown = async (): Promise<boolean> => {
		if (this.websocket) {
			const evt: CloseEvent = await this.websocket.close();
			this.websocket = null;
			return Promise.resolve(evt.type === 'close' && evt.wasClean);
		}

		return Promise.resolve(true);
	};

	setPassword = async (password: string): Promise<void> => {
		await this.rpc('set_password', password);
		this.password = password;
	};

	getDefaults = async (): Promise<unknown> => {
		const defaults = await this.rpc('get_default_config_gen_params', null);
		console.log('get_default_config_gen_params result', defaults);
		return defaults;
	};

	getStatus = async (): Promise<string> => {
		const result = await this.rpc('status', null);
		console.log('status result', result);
		return result as string;
	};

	setConnections = async (
		ourName: string,
		leaderUrl?: string
	): Promise<void> => {
		const connections = {
			our_name: ourName, // FIXME: make the call twice, second time with our_name
			leader_api_url: leaderUrl,
		};
		const defaults = await this.rpc('set_config_gen_connections', connections);
		console.log('set_config_gen_connections result', defaults);
	};

	awaitPeers = async (numPeers: number): Promise<void> => {
		const result = await this.rpc('await_config_gen_peers', numPeers); // not authenticated
		console.log('await_config_gen_peers result', result);
	};

	getVerifyConfigHash = async (): Promise<string> => {
		const hash = await this.rpc('get_verify_config_hash', null);
		console.log('get_verify_config_hash result', hash);
		return hash as string;
	};

	verifyConfigs = async (configHashes: string[]): Promise<void> => {
		const result = await this.rpc('verify_configs', configHashes);
		console.log('verify_config result', result);
	};

	getConsensusParams = async (): Promise<string> => {
		const result = await this.rpc('get_consensus_config_gen_params', null);
		console.log('get_consensus_config_gen_params result', result);
		return result as string;
	};

	runDkg = async (): Promise<void> => {
		const result = await this.rpc('run_dkg', null);
		console.log('run_dkg result', result);
	};

	startConsensus = async (): Promise<void> => {
		const result = await this.rpc('start_consensus', this.password);
		console.log('start_consensus result', result);
	};
}

export class NoopGuardianApi implements ApiInterface {
	setPassword = async (_password: string): Promise<void> => {
		return;
	};
	setConnections = async (
		_ourName: string,
		_leaderUrl?: string
	): Promise<void> => {
		return;
	};
	getDefaults = async (): Promise<unknown> => {
		return;
	};
	getStatus = async (): Promise<string> => {
		return 'noop';
	};
	getConsensusParams = async (): Promise<unknown> => {
		return;
	};
	getVerifyConfigHash = async (): Promise<string> => {
		return 'noop';
	};
	awaitPeers = async (_numPeers: number): Promise<void> => {
		return;
	};
	runDkg = async (): Promise<void> => {
		return;
	};
	verifyConfigs = async (_configHashes: string[]): Promise<void> => {
		return;
	};
	startConsensus = async (): Promise<void> => {
		return;
	};
	shutdown = async (): Promise<boolean> => {
		return true;
	};
}

import { JsonRpcError, JsonRpcWebsocket } from 'jsonrpc-client-websocket';

export interface ApiInterface {
	ping: () => Promise<string>;
	loggedIn: () => boolean;
	setPassword: (password: string) => Promise<void>;
	runDkg: () => Promise<void>;
}

async function rpc<T>(method: string, params: any): Promise<T> {
	const websocketUrl = 'ws://127.0.0.1:18174';
	const requestTimeoutMs = 2000;
	const websocket = new JsonRpcWebsocket(websocketUrl, requestTimeoutMs, (error: JsonRpcError) => {
		/* handle error */
		console.error('failed to create websocket', error);
	});
	await websocket.open();
	const response = await websocket.call(method, [{
		// FIXME: allow for this
		auth: null,
		params
	}]);
	return response.result as T;
}

export class Api implements ApiInterface {
	password: string | null;

	constructor() {
		this.password = null;
	}

	loggedIn = (): boolean => {
		return this.password !== null;
	};

	ping = async (): Promise<string> => {
		return await rpc('ping', null);
	};

	setPassword = async (password: string): Promise<void> => {
		await rpc('set_password', password);
		this.password = password;
	};

	runDkg = async (): Promise<void> => {
		await rpc('run_dkg', null);
	};
}

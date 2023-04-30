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
  private password: string | null;
  private websocket: JsonRpcWebsocket | null;

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
    return this.websocket;
  };

  private rpc = async <P, T>(
    method: string,
    params: P,
    authenticated: boolean
  ): Promise<T> => {
    try {
      const websocket = await this.connect();

      const response = await websocket.call(method, [
        {
          auth: authenticated ? this.password : null,
          params,
        },
      ]);

      if (response.error) {
        throw response.error;
      }

      const result = response.result as T;
      console.log(`${method} rpc result:`, result);

      return result;
    } catch (error) {
      console.error(`error calling "${method}" on websocket rpc : `, error);
      throw error;
    }
  };

  setPassword = async (password: string): Promise<void> => {
    await this.rpc<string, void>(
      'set_password',
      password,
      false /* not-authenticated */
    );
    this.password = password;

    return;
  };

  setConnections = async (
    ourName: string,
    leaderUrl?: string
  ): Promise<void> => {
    const connections = {
      our_name: ourName,
      leader_api_url: leaderUrl,
    };

    return this.rpc(
      'set_config_gen_connections',
      connections,
      true /* authenticated */
    );
  };

  getDefaults = async (): Promise<unknown> => {
    return this.rpc(
      'get_default_config_gen_params',
      null,
      true /* authenticated */
    );
  };

  getStatus = async (): Promise<string> => {
    return this.rpc('status', null, true /* authenticated */);
  };

  getConsensusParams = async (): Promise<string> => {
    return this.rpc(
      'get_consensus_config_gen_params',
      null,
      true /* authenticated */
    );
  };

  getVerifyConfigHash = async (): Promise<string> => {
    return this.rpc('get_verify_config_hash', null, true /* authenticated */);
  };

  awaitPeers = async (numPeers: number): Promise<void> => {
    // not authenticated
    return this.rpc(
      'await_config_gen_peers',
      numPeers,
      false /* not-authenticated */
    );
  };

  runDkg = async (): Promise<void> => {
    return this.rpc('run_dkg', null, true /* authenticated */);
  };

  verifyConfigs = async (configHashes: string[]): Promise<void> => {
    return this.rpc('verify_configs', configHashes, true /* authenticated */);
  };

  startConsensus = async (): Promise<void> => {
    if (this.password === null) {
      throw new Error('password not set');
    }

    return this.rpc('start_consensus', this.password, true /* authenticated */);
  };

  shutdown = async (): Promise<boolean> => {
    if (this.websocket) {
      const evt: CloseEvent = await this.websocket.close();
      this.websocket = null;
      return evt.type === 'close' && evt.wasClean;
    }

    return true;
  };
}

/* eslint-disable @typescript-eslint/no-unused-vars */

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

/* eslint-enable @typescript-eslint/no-unused-vars */

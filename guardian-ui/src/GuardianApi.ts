import { JsonRpcError, JsonRpcWebsocket } from 'jsonrpc-client-websocket';
import { ConfigGenParams, ConsensusState, ServerStatus } from './types';

export interface ApiInterface {
  testPassword: (password: string) => Promise<boolean>;
  setPassword: (password: string) => Promise<void>;
  getPassword: () => string | null;
  setConfigGenConnections: (
    ourName: string,
    leaderUrl?: string
  ) => Promise<void>;
  getDefaultConfigGenParams: () => Promise<ConfigGenParams>;
  status: () => Promise<ServerStatus>;
  getConsensusConfigGenParams: () => Promise<ConsensusState>;
  setConfigGenParams: (params: ConfigGenParams) => Promise<void>;
  getVerifyConfigHash: () => Promise<string>;
  awaitConfigGenPeers: (numPeers: number) => Promise<void>;
  runDkg: () => Promise<void>;
  verifyConfigs: (configHashes: string[]) => Promise<void>;
  startConsensus: () => Promise<void>;
  shutdown: () => Promise<boolean>;
}

const SESSION_STORAGE_KEY = 'guardian-ui-key';

export class GuardianApi implements ApiInterface {
  private websocket: JsonRpcWebsocket | null = null;
  private connectPromise: Promise<JsonRpcWebsocket> | null = null;

  public connect = async (): Promise<JsonRpcWebsocket> => {
    if (this.websocket !== null) {
      return this.websocket;
    }
    if (this.connectPromise) {
      return await this.connectPromise;
    }

    this.connectPromise = new Promise((resolve, reject) => {
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
          reject(error);
          this.shutdown();
        }
      );
      websocket
        .open()
        .then(() => {
          this.websocket = websocket;
          resolve(this.websocket);
        })
        .catch((error) => {
          console.error('failed to open websocket', error);
          reject(
            new Error(
              'Failed to connect to API, confirm your server is online and try again.'
            )
          );
        });
    });

    return this.connectPromise;
  };

  public getPassword = (): string | null => {
    return sessionStorage.getItem(SESSION_STORAGE_KEY);
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
          auth: authenticated ? this.getPassword() : null,
          params,
        },
      ]);

      if (response.error) {
        throw response.error;
      }

      const result = response.result as T;
      console.log(`${method} rpc result:`, result);

      return result;
    } catch (error: unknown) {
      console.error(`error calling "${method}" on websocket rpc : `, error);
      throw 'error' in (error as { error: JsonRpcError })
        ? (error as { error: JsonRpcError }).error
        : error;
    }
  };

  testPassword = async (password: string): Promise<boolean> => {
    // Replace with password to check.
    sessionStorage.setItem(SESSION_STORAGE_KEY, password);

    // Attempt a "status" rpc call with the temporary password.
    try {
      await this.status();
      return true;
    } catch (err) {
      // TODO: make sure error is auth error, not unrelated
      this.clearPassword();
      return false;
    }
  };

  setPassword = async (password: string): Promise<void> => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, password);

    return this.rpc('set_password', null, true /* authenticated */);
  };

  private clearPassword = () => {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  };

  setConfigGenConnections = async (
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

  getDefaultConfigGenParams = async (): Promise<ConfigGenParams> => {
    let params: ConfigGenParams;
    try {
      params = await this.rpc(
        'get_default_config_gen_params',
        null,
        false /* not-authenticated */
      );
    } catch (err) {
      params = await this.rpc(
        'get_default_config_gen_params',
        null,
        true /* authenticated */
      );
    }
    return params;
  };

  status = async (): Promise<ServerStatus> => {
    return this.rpc('status', null, true /* authenticated */);
  };

  getConsensusConfigGenParams = async (): Promise<ConsensusState> => {
    return this.rpc(
      'get_consensus_config_gen_params',
      null,
      false /* not-authenticated */
    );
  };

  // FIXME
  setConfigGenParams = async (params: ConfigGenParams): Promise<void> => {
    return this.rpc('set_config_gen_params', params, true /* authenticated */);
  };

  getVerifyConfigHash = async (): Promise<string> => {
    return this.rpc('get_verify_config_hash', null, true /* authenticated */);
  };

  awaitConfigGenPeers = async (numPeers: number): Promise<void> => {
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
    if (this.getPassword() === null) {
      throw new Error('password not set');
    }

    return this.rpc('start_consensus', null, true /* authenticated */);
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
  testPassword = () => Promise.resolve(false);
  setPassword = async (_password: string): Promise<void> => {
    return;
  };
  getPassword = () => null;
  setConfigGenConnections = async (
    _ourName: string,
    _leaderUrl?: string
  ): Promise<void> => {
    return;
  };
  getDefaultConfigGenParams = async (): Promise<ConfigGenParams> => {
    throw 'not implemented';
  };
  status = async (): Promise<ServerStatus> => {
    throw 'not implemented';
  };
  getConsensusConfigGenParams = async (): Promise<ConsensusState> => {
    throw 'not implemented';
  };
  setConfigGenParams = async (_params: ConfigGenParams): Promise<void> => {
    return;
  };
  getVerifyConfigHash = async (): Promise<string> => {
    throw 'not implemented';
  };
  awaitConfigGenPeers = async (_numPeers: number): Promise<void> => {
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

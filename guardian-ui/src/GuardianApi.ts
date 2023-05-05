import { JsonRpcError, JsonRpcWebsocket } from 'jsonrpc-client-websocket';
import {
  ConfigGenParams,
  ConsensusState,
  ConsensusStatus,
  PeerHashMap,
  ServerStatus,
  Versions,
} from './types';

export interface ApiInterface {
  // WebSocket methods
  connect(): Promise<JsonRpcWebsocket>;
  shutdown: () => Promise<boolean>;
  getPassword: () => string | null;
  testPassword: (password: string) => Promise<boolean>;

  // Shared RPC methods
  status: () => Promise<ServerStatus>;

  // Setup RPC methods (only exist during setup)
  setPassword: (password: string) => Promise<void>;
  setConfigGenConnections: (
    ourName: string,
    leaderUrl?: string
  ) => Promise<void>;
  getDefaultConfigGenParams: () => Promise<ConfigGenParams>;
  getConsensusConfigGenParams: () => Promise<ConsensusState>;
  setConfigGenParams: (params: ConfigGenParams) => Promise<void>;
  getVerifyConfigHash: () => Promise<PeerHashMap>;
  runDkg: () => Promise<void>;
  startConsensus: () => Promise<void>;

  // Running RPC methods (only exist after run_consensus)
  version: () => Promise<Versions>;
  fetchEpochCount: () => Promise<number>;
  consensusStatus: () => Promise<ConsensusStatus>;
}

const SESSION_STORAGE_KEY = 'guardian-ui-key';

export class GuardianApi implements ApiInterface {
  private websocket: JsonRpcWebsocket | null = null;
  private connectPromise: Promise<JsonRpcWebsocket> | null = null;

  /*** WebSocket methods ***/

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

  shutdown = async (): Promise<boolean> => {
    if (this.websocket) {
      const evt: CloseEvent = await this.websocket.close();
      this.websocket = null;
      return evt.type === 'close' && evt.wasClean;
    }

    return true;
  };

  getPassword = (): string | null => {
    return sessionStorage.getItem(SESSION_STORAGE_KEY);
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

  /*** Shared RPC methods */

  status = async (): Promise<ServerStatus> => {
    return this.rpc('status', null, true /* authenticated */);
  };

  /*** Setup RPC methods ***/

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

  getConsensusConfigGenParams = async (): Promise<ConsensusState> => {
    return this.rpc(
      'get_consensus_config_gen_params',
      null,
      false /* not-authenticated */
    );
  };

  setConfigGenParams = async (params: ConfigGenParams): Promise<void> => {
    return this.rpc('set_config_gen_params', params, true /* authenticated */);
  };

  getVerifyConfigHash = async (): Promise<PeerHashMap> => {
    return this.rpc('get_verify_config_hash', null, true /* authenticated */);
  };

  runDkg = async (): Promise<void> => {
    return this.rpc('run_dkg', null, true /* authenticated */);
  };

  startConsensus = async (): Promise<void> => {
    if (this.getPassword() === null) {
      throw new Error('password not set');
    }

    return this.rpc('start_consensus', null, true /* authenticated */);
  };

  /*** Running RPC methods */

  version = async (): Promise<Versions> => {
    return this.rpc('version', null, true);
  };

  fetchEpochCount = async (): Promise<number> => {
    return this.rpc('fetch_epoch_count', null, true);
  };

  consensusStatus = async (): Promise<ConsensusStatus> => {
    return this.rpc('consensus_status', null, true);
  };

  /*** Internal private methods ***/

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
}

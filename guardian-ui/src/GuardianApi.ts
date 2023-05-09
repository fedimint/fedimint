import { JsonRpcError, JsonRpcWebsocket } from 'jsonrpc-client-websocket';
import {
  ConfigGenParams,
  ConsensusState,
  ConsensusStatus,
  PeerHashMap,
  ServerStatus,
  StatusResponse,
  Versions,
} from './types';

export interface ApiInterface {
  // WebSocket methods
  connect(): Promise<JsonRpcWebsocket>;
  shutdown: () => Promise<boolean>;
  getPassword: () => string | null;
  testPassword: (password: string) => Promise<boolean>;

  // Shared RPC methods
  status: () => Promise<StatusResponse>;

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
    if (this.connectPromise) {
      this.connectPromise = null;
    }
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

  status = (): Promise<StatusResponse> => {
    return this.rpc('status');
  };

  /*** Setup RPC methods ***/

  setPassword = async (password: string): Promise<void> => {
    sessionStorage.setItem(SESSION_STORAGE_KEY, password);

    return this.rpc('set_password');
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

    return this.rpc('set_config_gen_connections', connections);
  };

  getDefaultConfigGenParams = (): Promise<ConfigGenParams> => {
    return this.rpc('get_default_config_gen_params');
  };

  getConsensusConfigGenParams = (): Promise<ConsensusState> => {
    return this.rpc('get_consensus_config_gen_params');
  };

  setConfigGenParams = (params: ConfigGenParams): Promise<void> => {
    return this.rpc('set_config_gen_params', params);
  };

  getVerifyConfigHash = (): Promise<PeerHashMap> => {
    return this.rpc('get_verify_config_hash');
  };

  runDkg = (): Promise<void> => {
    return this.rpc('run_dkg');
  };

  startConsensus = async (): Promise<void> => {
    const sleep = (time: number) =>
      new Promise((resolve) => setTimeout(resolve, time));

    // Special case: start_consensus kills the server, which sometimes causes it not to respond.
    // If it doesn't respond within 5 seconds, continue on with status checks.
    await Promise.any([this.rpc<null>('start_consensus'), sleep(5000)]);

    // Try to reconnect and confirm that status is ConsensusRunning. Retry multiple
    // times, but eventually give up and just throw.
    let tries = 0;
    const maxTries = 10;
    const attempConfirmConsensusRunning = async (): Promise<void> => {
      // Explicitly start a fresh socket.
      await this.shutdown();
      await this.connect();
      // Confirm status.
      try {
        const status = await this.status();
        if (status.server === ServerStatus.ConsensusRunning) {
          return;
        } else {
          throw new Error(
            `Expected status ConsensusRunning, got ${status.server}`
          );
        }
      } catch (err) {
        console.warn('Failed to confirm consensus running:', err);
      }
      // Retry after a delay if we haven't exceeded the max number of tries, otherwise give up.
      if (tries < maxTries) {
        tries++;
        await sleep(1000);
        return attempConfirmConsensusRunning();
      } else {
        throw new Error('Failed to start consensus, see logs for more info.');
      }
    };

    return attempConfirmConsensusRunning();
  };

  /*** Running RPC methods */

  version = (): Promise<Versions> => {
    return this.rpc('version');
  };

  fetchEpochCount = (): Promise<number> => {
    return this.rpc('fetch_epoch_count');
  };

  consensusStatus = (): Promise<ConsensusStatus> => {
    return this.rpc('consensus_status');
  };

  /*** Internal private methods ***/

  private rpc = async <T>(
    method: string,
    params: object | null = null
  ): Promise<T> => {
    try {
      const websocket = await this.connect();

      const response = await websocket.call(method, [
        {
          auth: this.getPassword() || null,
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

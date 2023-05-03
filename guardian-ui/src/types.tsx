export enum GuardianRole {
  Host = 'Host',
  Follower = 'Follower',
}

export enum SetupProgress {
  Start = 'Start',
  SetConfiguration = 'SetConfiguration',
  ConnectGuardians = 'ConnectGuardians',
  VerifyGuardians = 'VerifyGuardians',
  SetupComplete = 'SetupComplete',
}

export enum ServerStatus {
  AwaitingPassword = 'AwaitingPassword',
  GeneratingConfig = 'GeneratingConfig',
  Upgrading = 'Upgrading',
  ConsensusRunning = 'ConsensusRunning',
}

export enum Network {
  Testnet = 'testnet',
  Mainnet = 'mainnet',
  Regtest = 'regtest',
  Signet = 'signet',
}

export interface Peer {
  name: string;
  cert: string;
  api_url: string;
  p2p_url: string;
}

export type API_ConfigGenParams = {
  meta: { federation_name: string };
  modules: {
    wallet: { finality_delay: number; network: Network };
    mint: { mint_amounts: number[] };
  };
};

export type ConfigGenParams = {
  meta: { federationName: string };
  modules: {
    wallet: { finalityDelay: number; network: Network };
    mint: { mintAmounts: number[] };
  };
};

export interface ConsensusState {
  requested: ConfigGenParams;
  peers: Peer[];
}

export interface SetupState {
  role: GuardianRole | null;
  progress: SetupProgress;
  myName: string;
  password: string;
  configGenParams: ConfigGenParams | null;
  numPeers: number;
  peers: Peer[];
  myVerificationCode: string;
  peerVerificationCodes: string[];
  federationConnectionString: string;
}

export enum SETUP_ACTION_TYPE {
  SET_INITIAL_STATE = 'SET_INITIAL_STATE',
  SET_ROLE = 'SET_ROLE',
  SET_PROGRESS = 'SET_PROGRESS',
  SET_MY_NAME = 'SET_MY_NAME',
  SET_PASSWORD = 'SET_PASSWORD',
  SET_CONFIG_GEN_PARAMS = 'SET_CONFIG_GEN_PARAMS',
  SET_NUM_PEERS = 'SET_NUM_PEERS',
  SET_PEERS = 'SET_PEERS',
  SET_MY_VERIFICATION_CODE = 'SET_MY_VERIFICATION_CODE',
  SET_PEER_VERIFICATION_CODES = 'SET_PEER_VERIFICATION_CODES',
  SET_FEDERATION_CONNECTION_STRING = 'SET_FEDERATION_CONNECTION_STRING',
}

export type SetupAction =
  | {
      type: SETUP_ACTION_TYPE.SET_INITIAL_STATE;
      payload: null;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_ROLE;
      payload: GuardianRole;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_PROGRESS;
      payload: SetupProgress;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_MY_NAME;
      payload: string;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS;
      payload: ConfigGenParams | null;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_PASSWORD;
      payload: string;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_NUM_PEERS;
      payload: number;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_PEERS;
      payload: Peer[];
    }
  | {
      type: SETUP_ACTION_TYPE.SET_MY_VERIFICATION_CODE;
      payload: string;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_PEER_VERIFICATION_CODES;
      payload: string[];
    }
  | {
      type: SETUP_ACTION_TYPE.SET_FEDERATION_CONNECTION_STRING;
      payload: string;
    };

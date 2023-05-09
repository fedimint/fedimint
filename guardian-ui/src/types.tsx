export enum GuardianRole {
  Host = 'Host',
  Follower = 'Follower',
}

export enum SetupProgress {
  Start = 'Start',
  SetConfiguration = 'SetConfiguration',
  ConnectGuardians = 'ConnectGuardians',
  RunDKG = 'RunDKG',
  VerifyGuardians = 'VerifyGuardians',
  SetupComplete = 'SetupComplete',
}

export enum ServerStatus {
  AwaitingPassword = 'AwaitingPassword',
  SharingConfigGenParams = 'SharingConfigGenParams',
  ReadyForConfigGen = 'ReadyForConfigGen',
  ConfigGenFailed = 'ConfigGenFailed',
  VerifyingConfigs = 'VerifyingConfigs',
  Upgrading = 'Upgrading',
  ConsensusRunning = 'ConsensusRunning',
}

export interface StatusResponse {
  server: ServerStatus;
  consensus: ConsensusStatus;
}

export enum PeerConnectionStatus {
  Connected = 'Connected',
  Disconnected = 'Disconnected',
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
  status: ServerStatus;
}

export type PeerHashMap = Record<string, string>;

export type LnFedimintModule = ['ln', null];
export type MintFedimintModule = ['mint', { mint_amounts: number[] }];
export type WalletFedimintModule = [
  'wallet',
  { finality_delay: number; network: Network }
];
export type OtherFedimintModule = [string, object | null];
export type AnyFedimintModule =
  | LnFedimintModule
  | MintFedimintModule
  | WalletFedimintModule
  | OtherFedimintModule;

export type ConfigGenParams = {
  meta: { federation_name: string };
  modules: Record<number, AnyFedimintModule>;
};

export interface ConsensusState {
  consensus: {
    requested: ConfigGenParams;
    peers: Record<string, Peer>;
  };
  our_current_id: number;
}

export interface Versions {
  core: {
    consensus: number;
    api: { major: number; minor: number }[];
  };
  modules: Record<
    number,
    {
      core: number;
      module: number;
      api: { major: number; minor: number }[];
    }
  >;
}

export interface PeerStatus {
  last_contribution?: number;
  last_contribution_timestamp_seconds?: number;
  connection_status: PeerConnectionStatus;
  flagged: boolean;
}

export interface ConsensusStatus {
  last_contribution: number;
  peers_online: number;
  peers_offline: number;
  peers_flagged: number;
  status_by_peer: Record<string, PeerStatus>;
}

export interface SetupState {
  isInitializing: boolean;
  role: GuardianRole | null;
  progress: SetupProgress;
  myName: string;
  password: string;
  configGenParams: ConfigGenParams | null;
  numPeers: number;
  needsAuth: boolean;
  peers: Peer[];
  isSetupComplete: boolean;
}

export enum SETUP_ACTION_TYPE {
  SET_IS_INITIALIZING = 'SET_IS_INITIALIZING',
  SET_INITIAL_STATE = 'SET_INITIAL_STATE',
  SET_ROLE = 'SET_ROLE',
  SET_PROGRESS = 'SET_PROGRESS',
  SET_MY_NAME = 'SET_MY_NAME',
  SET_PASSWORD = 'SET_PASSWORD',
  SET_NEEDS_AUTH = 'SET_NEEDS_AUTH',
  SET_CONFIG_GEN_PARAMS = 'SET_CONFIG_GEN_PARAMS',
  SET_NUM_PEERS = 'SET_NUM_PEERS',
  SET_PEERS = 'SET_PEERS',
  SET_IS_SETUP_COMPLETE = 'SET_IS_SETUP_COMPLETE',
}

export type SetupAction =
  | {
      type: SETUP_ACTION_TYPE.SET_INITIAL_STATE;
      payload: null;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_IS_INITIALIZING;
      payload: boolean;
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
      type: SETUP_ACTION_TYPE.SET_NEEDS_AUTH;
      payload: boolean;
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
      type: SETUP_ACTION_TYPE.SET_IS_SETUP_COMPLETE;
      payload: boolean;
    };

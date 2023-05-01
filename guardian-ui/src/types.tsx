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

export enum Network {
  Testnet = 'testnet',
  Mainnet = 'mainnet',
  Regtest = 'regtest',
  Signet = 'signet',
}

export interface Peer {
  name: string;
  status: PeerStatus;
}

export interface PeerStatus {
  connected: boolean;
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

export interface SetupState {
  role: GuardianRole | null;
  progress: SetupProgress;
  myName: string;
  federationName: string;
  finalityDelay: number;
  network: Network | null;
  password: string;
  numPeers: number;
  peers: Peer[];
  myVerificationCode: string;
  peerVerificationCodes: string[];
  federationConnectionString: string;
}

export enum SETUP_ACTION_TYPE {
  SET_ROLE = 'SET_ROLE',
  SET_PROGRESS = 'SET_PROGRESS',
  SET_MY_NAME = 'SET_MY_NAME',
  SET_FEDERATION_NAME = 'SET_FEDERATION_NAME',
  SET_FINALITY_DELAY = 'SET_FINALITY_DELAY',
  SET_NETWORK = 'SET_NETWORK',
  SET_PASSWORD = 'SET_PASSWORD',
  SET_NUM_PEERS = 'SET_NUM_PEERS',
  SET_PEERS = 'SET_PEERS',
  SET_MY_VERIFICATION_CODE = 'SET_MY_VERIFICATION_CODE',
  SET_PEER_VERIFICATION_CODES = 'SET_PEER_VERIFICATION_CODES',
  SET_FEDERATION_CONNECTION_STRING = 'SET_FEDERATION_CONNECTION_STRING',
}

export type SetupAction =
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
      type: SETUP_ACTION_TYPE.SET_FEDERATION_NAME;
      payload: string;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_FINALITY_DELAY;
      payload: number;
    }
  | {
      type: SETUP_ACTION_TYPE.SET_NETWORK;
      payload: Network;
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

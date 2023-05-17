import React, {
  createContext,
  Dispatch,
  ReactNode,
  useCallback,
  useEffect,
  useReducer,
  useState,
} from 'react';
import {
  SetupState,
  SetupAction,
  SETUP_ACTION_TYPE,
  SetupProgress,
  ConfigGenParams,
  ConsensusState,
  ServerStatus,
} from './types';
import { ApiInterface, GuardianApi } from './GuardianApi';
import { JsonRpcError } from 'jsonrpc-client-websocket';

const LOCAL_STORAGE_KEY = 'guardian-ui-state';

/**
 * Creates the initial state using loaded state from local storage.
 */
function makeInitialState(loadFromStorage = true): SetupState {
  let storageState: Partial<SetupState> = {};
  if (loadFromStorage) {
    try {
      const storageJson = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (storageJson) {
        storageState = JSON.parse(storageJson);
      }
    } catch (err) {
      console.warn('Encountered error while fetching storage state', err);
    }
  }

  return {
    isInitializing: true,
    role: null,
    progress: SetupProgress.Start,
    myName: '',
    configGenParams: null,
    password: '',
    needsAuth: false,
    numPeers: 0,
    peers: [],
    isSetupComplete: false,
    ...storageState,
  };
}

const initialState = makeInitialState();

const reducer = (state: SetupState, action: SetupAction): SetupState => {
  switch (action.type) {
    case SETUP_ACTION_TYPE.SET_INITIAL_STATE:
      return makeInitialState(false);
    case SETUP_ACTION_TYPE.SET_IS_INITIALIZING:
      return { ...state, isInitializing: action.payload };
    case SETUP_ACTION_TYPE.SET_ROLE:
      return { ...state, role: action.payload };
    case SETUP_ACTION_TYPE.SET_PROGRESS:
      return { ...state, progress: action.payload };
    case SETUP_ACTION_TYPE.SET_MY_NAME:
      return { ...state, myName: action.payload };
    case SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS:
      return { ...state, configGenParams: action.payload };
    case SETUP_ACTION_TYPE.SET_PASSWORD:
      return { ...state, password: action.payload, needsAuth: false };
    case SETUP_ACTION_TYPE.SET_NEEDS_AUTH:
      return { ...state, needsAuth: action.payload };
    case SETUP_ACTION_TYPE.SET_NUM_PEERS:
      return { ...state, numPeers: action.payload };
    case SETUP_ACTION_TYPE.SET_PEERS:
      return { ...state, peers: action.payload };
    case SETUP_ACTION_TYPE.SET_IS_SETUP_COMPLETE:
      return { ...state, isSetupComplete: action.payload };
    default:
      return state;
  }
};

export interface GuardianContextValue {
  api: ApiInterface;
  state: SetupState;
  dispatch: Dispatch<SetupAction>;
  submitFollowerConfiguration(config: {
    myName: string;
    password: string;
    hostServerUrl: string;
  }): Promise<void>;
  submitHostConfiguration(config: {
    password: string;
    myName: string;
    numPeers: number;
    config: ConfigGenParams;
  }): Promise<void>;
  connectToHost(url: string): Promise<ConsensusState>;
  fetchConsensusState(): Promise<ConsensusState>;
  toggleConsensusPolling(toggle: boolean): void;
}

export const GuardianContext = createContext<GuardianContextValue>({
  api: new GuardianApi(),
  state: initialState,
  dispatch: () => null,
  submitFollowerConfiguration: () => Promise.reject(),
  submitHostConfiguration: () => Promise.reject(),
  connectToHost: () => Promise.reject(),
  fetchConsensusState: () => Promise.reject(),
  toggleConsensusPolling: () => null,
});

export interface GuardianProviderProps {
  api: ApiInterface;
  children: ReactNode;
}

export const GuardianProvider: React.FC<GuardianProviderProps> = ({
  api,
  children,
}: GuardianProviderProps) => {
  const [state, dispatch] = useReducer(reducer, initialState);
  const { password, configGenParams, myName } = state;
  const [isPollingConsensus, setIsPollingConsensus] = useState(false);

  // On mount, fetch what status the server has us at, and set state accordingly.
  useEffect(() => {
    api
      .status()
      .then((status) => {
        // If we're still waiting for a password, restart the whole thing.
        // Otherwise, fetch the password and indicate if we need auth.
        if (status.server === ServerStatus.AwaitingPassword) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_INITIAL_STATE,
            payload: null,
          });
        } else {
          const apiPassword = api.getPassword();
          if (apiPassword) {
            dispatch({
              type: SETUP_ACTION_TYPE.SET_PASSWORD,
              payload: apiPassword,
            });
          } else {
            dispatch({
              type: SETUP_ACTION_TYPE.SET_NEEDS_AUTH,
              payload: true,
            });
          }
        }
        // If we're ready for DKG, move them to approve the config to start.
        if (status.server === ServerStatus.ReadyForConfigGen) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_PROGRESS,
            payload: SetupProgress.ConnectGuardians,
          });
        }
        // If we're supposed to be verifying, jump to peer validation screen
        if (status.server === ServerStatus.VerifyingConfigs) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_PROGRESS,
            payload: SetupProgress.VerifyGuardians,
          });
        }
        // If consensus is running, skip past all setup
        if (status.server === ServerStatus.ConsensusRunning) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_IS_SETUP_COMPLETE,
            payload: true,
          });
        }
      })
      .catch((err) => {
        // Missing password error
        if ((err as JsonRpcError).code === 401) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_NEEDS_AUTH,
            payload: true,
          });
        } else {
          // TODO: Present error to user
          console.error(err);
        }
      })
      .finally(() => {
        dispatch({
          type: SETUP_ACTION_TYPE.SET_IS_INITIALIZING,
          payload: false,
        });
      });
  }, [api]);

  useEffect(() => {
    // Fetch password from API on mount
    const apiPassword = api.getPassword();
    if (apiPassword) {
      dispatch({
        type: SETUP_ACTION_TYPE.SET_PASSWORD,
        payload: apiPassword,
      });
    }

    // Shut down API on dismount
    return () => {
      api.shutdown();
    };
  }, [api]);

  // Update local storage on state changes.
  useEffect(() => {
    localStorage.setItem(
      LOCAL_STORAGE_KEY,
      JSON.stringify({
        role: state.role,
        progress: state.progress,
        myName: state.myName,
        numPeers: state.numPeers,
        configGenParams: state.configGenParams,
      })
    );
  }, [
    state.role,
    state.progress,
    state.myName,
    state.numPeers,
    state.configGenParams,
  ]);

  // Fetch consensus state, dispatch updates with it.
  const fetchConsensusState = useCallback(async () => {
    const consensusState = await api.getConsensusConfigGenParams();
    dispatch({
      type: SETUP_ACTION_TYPE.SET_PEERS,
      payload: Object.values(consensusState.consensus.peers),
    });
    dispatch({
      type: SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS,
      payload: consensusState.consensus,
    });
    return consensusState;
  }, []);

  // Poll for peer state every 2 seconds when isPollingPeers.
  useEffect(() => {
    if (!isPollingConsensus) return;
    let timeout: ReturnType<typeof setTimeout>;
    const pollPeers = () => {
      fetchConsensusState()
        .catch((err) => {
          console.warn('Failed to poll for peers', err);
        })
        .finally(() => {
          timeout = setTimeout(pollPeers, 2000);
        });
    };
    pollPeers();
    return () => clearTimeout(timeout);
  }, [isPollingConsensus]);

  // Single call to save all of the configuration for followers.
  const submitFollowerConfiguration: GuardianContextValue['submitFollowerConfiguration'] =
    useCallback(
      async ({ myName, password: newPassword, hostServerUrl }) => {
        if (!password) {
          await api.setPassword(newPassword);
          dispatch({
            type: SETUP_ACTION_TYPE.SET_PASSWORD,
            payload: newPassword,
          });
        }

        dispatch({
          type: SETUP_ACTION_TYPE.SET_MY_NAME,
          payload: myName,
        });

        await api.setConfigGenConnections(myName, hostServerUrl);
        await fetchConsensusState();
      },
      [password, api, dispatch, fetchConsensusState]
    );

  // Single call to save all of the configuration for hosts.
  const submitHostConfiguration: GuardianContextValue['submitHostConfiguration'] =
    useCallback(
      async ({
        password: newPassword,
        myName,
        numPeers,
        config: newConfigGenParams,
      }) => {
        if (!password) {
          if (!configGenParams) {
            await api.setPassword(newPassword);
          }

          dispatch({
            type: SETUP_ACTION_TYPE.SET_PASSWORD,
            payload: newPassword,
          });
        }

        dispatch({ type: SETUP_ACTION_TYPE.SET_NUM_PEERS, payload: numPeers });
        dispatch({
          type: SETUP_ACTION_TYPE.SET_MY_NAME,
          payload: myName,
        });

        // Only host submits this, followers will connect to host in subsequent step.
        await api.setConfigGenConnections(myName);
        await api.setConfigGenParams(newConfigGenParams);
        dispatch({
          type: SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS,
          payload: newConfigGenParams,
        });
      },
      [password, api, dispatch, configGenParams]
    );

  const connectToHost = useCallback(
    async (url: string) => {
      await api.setConfigGenConnections(myName, url);
      return await fetchConsensusState();
    },
    [myName, api, dispatch]
  );

  const toggleConsensusPolling = useCallback((poll: boolean) => {
    setIsPollingConsensus(poll);
  }, []);

  return (
    <GuardianContext.Provider
      value={{
        state,
        dispatch,
        api,
        submitFollowerConfiguration,
        submitHostConfiguration,
        connectToHost,
        fetchConsensusState,
        toggleConsensusPolling,
      }}
    >
      {children}
    </GuardianContext.Provider>
  );
};

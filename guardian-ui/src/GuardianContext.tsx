import React, {
  createContext,
  Dispatch,
  ReactNode,
  useCallback,
  useEffect,
  useReducer,
} from 'react';
import {
  SetupState,
  SetupAction,
  SETUP_ACTION_TYPE,
  SetupProgress,
  ConfigGenParams,
  GuardianRole,
} from './types';
import { ApiInterface, NoopGuardianApi } from './GuardianApi';

const LOCAL_STORAGE_KEY = 'guardian-ui-state';

/**
 * Creates the initial state using loaded state from local storage.
 */
function makeInitialState(): SetupState {
  let storageState: Partial<SetupState> = {};
  try {
    const storageJson = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (storageJson) {
      storageState = JSON.parse(storageJson);
    }
  } catch (err) {
    console.warn('Encountered error while fetching storage state', err);
  }

  return {
    role: null,
    progress: SetupProgress.Start,
    myName: '',
    configGenParams: null,
    password: '',
    numPeers: 0,
    peers: [],
    myVerificationCode: '',
    peerVerificationCodes: [],
    federationConnectionString: '',
    ...storageState,
  };
}

const initialState = makeInitialState();

const reducer = (state: SetupState, action: SetupAction): SetupState => {
  switch (action.type) {
    case SETUP_ACTION_TYPE.SET_INITIAL_STATE:
      return initialState;
    case SETUP_ACTION_TYPE.SET_ROLE:
      return { ...state, role: action.payload };
    case SETUP_ACTION_TYPE.SET_PROGRESS:
      return { ...state, progress: action.payload };
    case SETUP_ACTION_TYPE.SET_MY_NAME:
      return { ...state, myName: action.payload };
    case SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS:
      return { ...state, configGenParams: action.payload };
    case SETUP_ACTION_TYPE.SET_PASSWORD:
      return { ...state, password: action.payload };
    case SETUP_ACTION_TYPE.SET_NUM_PEERS:
      return { ...state, numPeers: action.payload };
    case SETUP_ACTION_TYPE.SET_PEERS:
      return { ...state, peers: action.payload };
    case SETUP_ACTION_TYPE.SET_MY_VERIFICATION_CODE:
      return { ...state, myVerificationCode: action.payload };
    case SETUP_ACTION_TYPE.SET_PEER_VERIFICATION_CODES:
      return { ...state, peerVerificationCodes: action.payload };
    case SETUP_ACTION_TYPE.SET_FEDERATION_CONNECTION_STRING:
      return { ...state, federationConnectionString: action.payload };
    default:
      return state;
  }
};

export const GuardianContext = createContext<{
  api: ApiInterface;
  state: SetupState;
  dispatch: Dispatch<SetupAction>;
  submitConfiguration(config: {
    password: string;
    myName: string;
    numPeers: number;
    config: ConfigGenParams;
  }): Promise<void>;
}>({
  api: new NoopGuardianApi(),
  state: initialState,
  dispatch: () => null,
  submitConfiguration: () => Promise.resolve(),
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
  const { role, password, configGenParams } = state;

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
  }, []);

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

  // Single call save all of the configuration on the middle step and call various API methods.
  const submitConfiguration = useCallback(
    async ({
      password: newPassword,
      myName,
      numPeers,
      config: newConfigGenParams,
    }: {
      password: string;
      myName: string;
      numPeers: number;
      config: ConfigGenParams;
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
      if (role === GuardianRole.Host) {
        await api.setConfigGenConnections(myName);
        await api.setConfigGenParams(newConfigGenParams);
        dispatch({
          type: SETUP_ACTION_TYPE.SET_CONFIG_GEN_PARAMS,
          payload: newConfigGenParams,
        });
      }
    },
    [password, api, dispatch, configGenParams, role]
  );

  return (
    <GuardianContext.Provider
      value={{ state, dispatch, api, submitConfiguration }}
    >
      {children}
    </GuardianContext.Provider>
  );
};

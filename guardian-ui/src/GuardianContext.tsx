import React, { createContext, Dispatch, ReactNode, useReducer } from 'react';
import {
	SetupState,
	SetupAction,
	SETUP_ACTION_TYPE,
	SetupProgress,
	Network,
} from './types';

const initialState: SetupState = {
	role: null,
	progress: SetupProgress.Start,
	federationName: '',
	finalityDelay: 10,
	network: Network.Testnet,
	password: '',
	numPeers: 0,
	peers: [],
	myVerificationCode: '',
	peerVerificationCodes: [],
	federationConnectionString: '',
};

const reducer = (state: SetupState, action: SetupAction): SetupState => {
	switch (action.type) {
	case SETUP_ACTION_TYPE.SET_ROLE:
		return { ...state, role: action.payload };
	case SETUP_ACTION_TYPE.SET_PROGRESS:
		return { ...state, progress: action.payload };
	case SETUP_ACTION_TYPE.SET_FEDERATION_NAME:
		return { ...state, federationName: action.payload };
	case SETUP_ACTION_TYPE.SET_FINALITY_DELAY:
		return { ...state, finalityDelay: action.payload };
	case SETUP_ACTION_TYPE.SET_NETWORK:
		return { ...state, network: action.payload };
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
	state: SetupState;
	dispatch: Dispatch<SetupAction>;
}>({
	state: initialState,
	dispatch: () => null,
});

export interface GuardianProviderProps {
	children: ReactNode;
}

export const GuardianProvider: React.FC<GuardianProviderProps> = ({
	children,
}) => {
	const [state, dispatch] = useReducer(reducer, initialState);

	return (
		<GuardianContext.Provider value={{ state, dispatch }}>
			{children}
		</GuardianContext.Provider>
	);
};

import React, { createContext, Dispatch, ReactNode, useReducer } from 'react';

export type UserType = 'Host' | 'Non-Host';

interface State {
	step: number;
	userType: UserType | null;
}

type Action =
	| {
			type: ACTION_TYPE.SET_STEP;
			payload: number;
	  }
	| {
			type: ACTION_TYPE.SET_USER_TYPE;
			payload: UserType;
	  };

export enum ACTION_TYPE {
	SET_STEP = 'SET_STEP',
	SET_USER_TYPE = 'SET_USER_TYPE',
}

const initialState: State = {
	step: 1,
	userType: null,
};

const reducer = (state: State, action: Action): State => {
	switch (action.type) {
	case 'SET_STEP':
		return { ...state, step: action.payload };
	case 'SET_USER_TYPE':
		return { ...state, userType: action.payload };
	default:
		return state;
	}
};

const GuardianContext = createContext<{
	state: State;
	dispatch: Dispatch<Action>;
}>({
	state: initialState,
	dispatch: () => null,
});

interface GuardianProviderProps {
	children: ReactNode;
}

const GuardianProvider: React.FC<GuardianProviderProps> = ({ children }) => {
	const [state, dispatch] = useReducer(reducer, initialState);

	return (
		<GuardianContext.Provider value={{ state, dispatch }}>
			{children}
		</GuardianContext.Provider>
	);
};

export { GuardianContext, GuardianProvider };

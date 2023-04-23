import React from 'react';
import { ApiInterface, Api } from '../api';

interface ApiContextProps {
    api: ApiInterface
}

export const ApiContext = React.createContext<ApiContextProps>({
	api: new Api(),
});

export const ApiProvider = React.memo(function ApiProvider({
	props,
	children,
}: {
	props: ApiContextProps;
	children: React.ReactNode;
}): JSX.Element {
	return <ApiContext.Provider value={props}>{children}</ApiContext.Provider>;
});

import React from 'react';
import { Explorer, BlockstreamExplorer, Mintgate, MockMintgate } from '../api';

interface ApiContextProps {
	// API to interact with the Gateway server
	mintgate: Mintgate;
	explorer: Explorer;
}

// Using testnet blockstream explorer for all mocks
const mockExplorer = new BlockstreamExplorer(
	'https://blockstream.info/testnet/api/'
);

export const ApiContext = React.createContext<ApiContextProps>({
	mintgate: new MockMintgate(),
	explorer: mockExplorer,
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

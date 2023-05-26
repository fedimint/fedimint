import React from 'react';
import { GatewayApi } from './GatewayApi';
import { ExplorerApi } from './ExplorerApi';

interface ApiContextProps {
  // API to interact with the Gateway server
  gateway: GatewayApi;
  explorer: ExplorerApi;
}

export const ApiContext = React.createContext<ApiContextProps>({
  gateway: new GatewayApi(),
  explorer: new ExplorerApi('https://blockstream.info/api/'),
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

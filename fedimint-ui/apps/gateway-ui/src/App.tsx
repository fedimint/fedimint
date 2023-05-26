import React, { useState, useEffect, useMemo } from 'react';
import { Box, Center, Stack } from '@chakra-ui/react';
import {
  Header,
  FederationCard,
  ConnectFederation,
  ApiProvider,
} from './components';
import { GatewayApi } from './GatewayApi';
import { ExplorerApi } from './ExplorerApi';
import { GatewayInfo, Federation } from './types';

export const App = React.memo(function Admin(): JSX.Element {
  const gateway = useMemo(() => new GatewayApi(), []);
  const explorer = useMemo(
    () => new ExplorerApi('https://blockstream.info/api/'),
    []
  );

  const [gatewayInfo, setGatewayInfo] = useState<GatewayInfo>({
    federations: [],
    fees: {
      base_msat: 0,
      proportional_millionths: 0,
    },
    lightning_alias: '',
    lightning_pub_key: '',
    version_hash: '',
  });

  const [fedlist, setFedlist] = useState<Federation[]>([]);

  const [showConnectFed, toggleShowConnectFed] = useState<boolean>(false);

  useEffect(() => {
    gateway.fetchInfo().then((gatewayInfo: GatewayInfo) => {
      console.log(gatewayInfo);
      setGatewayInfo(gatewayInfo);
      setFedlist(gatewayInfo.federations);
    });
  }, [gateway]);

  const renderConnectedFedCallback = (federation: Federation) => {
    setFedlist([federation, ...fedlist]);
  };

  return (
    <ApiProvider props={{ gateway, explorer }}>
      <Center>
        <Box
          maxW='1000px'
          width='100%'
          mt={10}
          mb={10}
          mr={[2, 4, 6, 10]}
          ml={[2, 4, 6, 10]}
        >
          <Header
            gatewayInfo={gatewayInfo}
            toggleShowConnectFed={() => toggleShowConnectFed(!showConnectFed)}
          />
          <ConnectFederation
            isOpen={showConnectFed}
            renderConnectedFedCallback={renderConnectedFedCallback}
          />
          <Stack spacing={6} pt={6}>
            {fedlist.map((federation: Federation) => {
              return (
                <FederationCard
                  key={federation.mint_pubkey}
                  federation={federation}
                />
              );
            })}
          </Stack>
        </Box>
      </Center>
    </ApiProvider>
  );
});

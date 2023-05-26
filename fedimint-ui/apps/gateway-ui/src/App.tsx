import React, { useState, useEffect, useMemo } from 'react';
import { Box, Center, Stack } from '@chakra-ui/react';
import {
  Header,
  FederationCard,
  ConnectFederation,
  ApiProvider,
} from './components';
import { Federation, Filter, Sort } from './federation.types';
import { GatewayApi, GatewayInfo } from './GatewayApi';
import { ExplorerApi } from './ExplorerApi';

export const App = React.memo(function Admin(): JSX.Element {
  const gateway = useMemo(() => new GatewayApi(), []);
  const explorer = useMemo(
    () => new ExplorerApi('https://blockstream.info/api/'),
    []
  );

  const [gatewayInfo, setGatewayInfo] = useState<GatewayInfo>({
    version_hash: '',
    federations: [],
  });

  const [fedlist, setFedlist] = useState<Federation[]>([]);

  const [showConnectFed, toggleShowConnectFed] = useState<boolean>(false);

  useEffect(() => {
    gateway.fetchInfo().then((gatewayInfo: GatewayInfo) => {
      setGatewayInfo(gatewayInfo);
      setFedlist(gatewayInfo.federations);
    });
  }, [gateway]);

  const filterFederations = (filter: Filter) => {
    const federations =
      filter === undefined
        ? gatewayInfo.federations
        : gatewayInfo.federations.filter(
            (federation: Federation) => federation.details.active === filter
            // eslint-disable-next-line no-mixed-spaces-and-tabs
          );
    setFedlist(federations);
  };

  const sortFederations = (sort: Sort) => {
    const fedListCopy = [...fedlist];

    switch (sort) {
      case Sort.Ascending: {
        const result = fedListCopy.sort((a, b) =>
          a.details.name < b.details.name
            ? -1
            : a.details.name > b.details.name
            ? 1
            : 0
        );

        return setFedlist(result);
      }

      case Sort.Descending: {
        const result = fedListCopy.sort((a, b) =>
          a.details.name < b.details.name
            ? 1
            : a.details.name > b.details.name
            ? -1
            : 0
        );

        return setFedlist(result);
      }

      case Sort.Date: {
        const result = fedListCopy.sort((a, b) =>
          a.details.date_created < b.details.date_created
            ? 1
            : a.details.date_created > b.details.date_created
            ? -1
            : 0
        );

        return setFedlist(result);
      }

      default: {
        return setFedlist(gatewayInfo.federations);
      }
    }
  };

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
            data={gatewayInfo.federations}
            toggleShowConnectFed={() => toggleShowConnectFed(!showConnectFed)}
            filterCallback={filterFederations}
            sortCallback={sortFederations}
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
                  onClick={() => console.log('clicked')}
                />
              );
            })}
          </Stack>
        </Box>
      </Center>
    </ApiProvider>
  );
});

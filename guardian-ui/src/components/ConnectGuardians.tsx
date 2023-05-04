import {
  FormControl,
  FormLabel,
  Input,
  VStack,
  Button,
  FormHelperText,
  FormErrorMessage,
  Icon,
  useTheme,
  Spinner,
  TableContainer,
  Table as ChakraTable,
  Tbody,
  Tr,
  Td,
  HStack,
} from '@chakra-ui/react';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useGuardianContext } from '../hooks';
import { ConfigGenParams, GuardianRole } from '../types';
import { CopyInput } from './ui/CopyInput';
import { Table, TableRow } from './ui/Table';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { CheckCircleIcon } from '@chakra-ui/icons';
import { getModuleParamsFromConfig } from '../utils/api';

interface Props {
  next(): void;
}

export const ConnectGuardians: React.FC<Props> = ({ next }) => {
  const {
    state: { role, myName, peers, numPeers },
    api,
    togglePeerPolling,
  } = useGuardianContext();
  const theme = useTheme();
  const [consensusConfig, setConsensusConfig] = useState<ConfigGenParams>();
  const [hasCheckedForConsensusConfig, setHasCheckedForConsensusConfig] =
    useState(role !== GuardianRole.Follower);
  const [hostServerUrl, setHostServerUrl] = useState('');
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string>();

  const isAllConnected = numPeers && numPeers == peers.length;

  // For hosts, immediately start polling for peer state. For followers,
  // check if we already are connected + have consensus params. If so,
  // start polling. Otherwise we'll connect below in handleConnect.
  useEffect(() => {
    if (role === GuardianRole.Host) {
      togglePeerPolling(true);
    } else {
      api
        .getConsensusConfigGenParams()
        .then((res) => {
          setConsensusConfig(res.requested);
          togglePeerPolling(true);
        })
        .catch(() => null /* no-op */)
        .finally(() => setHasCheckedForConsensusConfig(true));
    }
  }, [role, api, togglePeerPolling]);

  // For hosts, once all peers have connected, run DKG immediately.
  useEffect(() => {
    if (role !== GuardianRole.Host || !isAllConnected) return;
    next();
  }, [role, isAllConnected, next]);

  const handleApprove = useCallback(() => {
    next();
  }, [api, next]);

  const handleConnect = useCallback(async () => {
    setConnectError(undefined);
    setIsConnecting(true);
    try {
      await api.setConfigGenConnections(myName, hostServerUrl);
      const res = await api.getConsensusConfigGenParams();
      setConsensusConfig(res.requested);
      togglePeerPolling(true);
    } catch (err: unknown) {
      console.log({ err });
      setConnectError('Failed to connect to host');
    }
    setIsConnecting(false);
  }, [myName, hostServerUrl, api, togglePeerPolling]);

  let content: React.ReactNode;
  if (!hasCheckedForConsensusConfig) {
    content = <Spinner />;
  } else if (role === GuardianRole.Host) {
    content = (
      <FormControl maxWidth={400}>
        <FormLabel>Invite Followers</FormLabel>
        <CopyInput
          value={process.env.REACT_APP_FM_CONFIG_API || ''}
          size='lg'
        />
        <FormHelperText>
          Share this link with the other Guardians
        </FormHelperText>
      </FormControl>
    );
  } else {
    let innerContent: React.ReactNode;
    if (consensusConfig) {
      // TODO: Consider making this more dynamic, work with unknown modules etc.
      const rows = [
        {
          label: 'Federation name',
          value: consensusConfig.meta.federation_name,
        },
        {
          label: 'Network',
          value: getModuleParamsFromConfig(consensusConfig, 'wallet')?.network,
        },
        {
          label: 'Block confirmations',
          value: getModuleParamsFromConfig(consensusConfig, 'wallet')
            ?.finality_delay,
        },
      ];
      innerContent = (
        <>
          <TableContainer width='100%'>
            <ChakraTable variant='simple'>
              <Tbody>
                {rows.map(({ label, value }) => (
                  <Tr key={label}>
                    <Td fontWeight='semibold'>{label}</Td>
                    <Td>{value}</Td>
                  </Tr>
                ))}
              </Tbody>
            </ChakraTable>
          </TableContainer>
          <div>
            <Button onClick={handleApprove}>Approve</Button>
          </div>
        </>
      );
    } else {
      innerContent = (
        <>
          <FormControl isInvalid={!!connectError}>
            <FormLabel>Leader server URL</FormLabel>
            <Input
              value={hostServerUrl}
              onChange={(ev) => setHostServerUrl(ev.currentTarget.value)}
              placeholder='ws://...'
              isDisabled={isConnecting}
            />
            {connectError ? (
              <FormErrorMessage>{connectError}</FormErrorMessage>
            ) : (
              <FormHelperText>
                Your leader will need to send this to you.
              </FormHelperText>
            )}
          </FormControl>

          <div>
            <Button
              isDisabled={!hostServerUrl}
              isLoading={isConnecting}
              leftIcon={<Icon as={ArrowRightIcon} />}
              onClick={handleConnect}
            >
              Connect
            </Button>
          </div>
        </>
      );
    }

    content = (
      <VStack gap={3} justify='start' align='start' width='100%' maxWidth={400}>
        {innerContent}
      </VStack>
    );
  }

  const peerTableColumns = useMemo(
    () =>
      [
        {
          key: 'name',
          heading: 'Name',
        },
        {
          key: 'status',
          heading: 'Status',
        },
      ] as const,
    []
  );

  const peerTableRows = useMemo(() => {
    let rows: TableRow<'name' | 'status'>[] = [];
    for (let i = 0; i < numPeers; i++) {
      const row = peers[i]
        ? {
            key: peers[i].cert,
            name: peers[i].name,
            status: (
              <HStack align='center'>
                <CheckCircleIcon boxSize={4} color={theme.colors.green[400]} />
                <span>Connected</span>
              </HStack>
            ),
          }
        : {
            key: i,
            name: `Guardian ${i + 1}`,
            status: (
              <HStack align='center'>
                <Spinner size='xs' />
                <span>Waiting</span>
              </HStack>
            ),
          };
      rows = [...rows, row];
    }
    return rows;
  }, [peers]);

  return (
    <VStack width='100%' justify='start' align='start' gap={8}>
      {content}
      {peerTableRows.length && (
        <Table
          title='Federation Guardians'
          description='Guardians will be confirmed here once they confirm Federation settings.'
          columns={peerTableColumns}
          rows={peerTableRows}
        />
      )}
    </VStack>
  );
};

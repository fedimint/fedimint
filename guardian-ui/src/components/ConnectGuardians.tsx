import {
  FormControl,
  FormLabel,
  VStack,
  Button,
  FormHelperText,
  useTheme,
  Spinner,
  TableContainer,
  Table as ChakraTable,
  Tbody,
  Tr,
  Td,
  HStack,
} from '@chakra-ui/react';
import React, { useCallback, useEffect, useMemo } from 'react';
import { useConsensusPolling, useGuardianContext } from '../hooks';
import { GuardianRole, ServerStatus } from '../types';
import { CopyInput } from './ui/CopyInput';
import { Table, TableRow } from './ui/Table';
import { CheckCircleIcon } from '@chakra-ui/icons';
import { getModuleParamsFromConfig } from '../utils/api';

interface Props {
  next(): void;
}

export const ConnectGuardians: React.FC<Props> = ({ next }) => {
  const {
    state: { role, peers, numPeers, configGenParams },
    api,
  } = useGuardianContext();
  const theme = useTheme();

  // Poll for peers and configGenParams while on this page.
  useConsensusPolling();

  const isAllConnected = numPeers && numPeers == peers.length;
  const isAllAccepted =
    isAllConnected &&
    peers.filter((peer) => peer.status === ServerStatus.ReadyForConfigGen)
      .length >=
      numPeers - 1;

  // For hosts, once all peers have connected, run DKG immediately.
  useEffect(() => {
    if (role !== GuardianRole.Host || !isAllAccepted) return;
    next();
  }, [role, isAllAccepted, next]);

  const handleApprove = useCallback(() => {
    next();
  }, [api, next]);

  let content: React.ReactNode;
  if (!configGenParams) {
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
    // TODO: Consider making this more dynamic, work with unknown modules etc.
    const rows = [
      {
        label: 'Federation name',
        value: configGenParams.meta.federation_name,
      },
      {
        label: 'Network',
        value: getModuleParamsFromConfig(configGenParams, 'wallet')?.network,
      },
      {
        label: 'Block confirmations',
        value: getModuleParamsFromConfig(configGenParams, 'wallet')
          ?.finality_delay,
      },
    ];

    content = (
      <VStack gap={3} justify='start' align='start' width='100%' maxWidth={400}>
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

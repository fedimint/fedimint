import React, { useCallback, useEffect, useMemo } from 'react';
import {
  FormControl,
  FormLabel,
  VStack,
  Button,
  FormHelperText,
  Spinner,
  TableContainer,
  Table as ChakraTable,
  Tbody,
  Tr,
  Td,
  Tag,
  Icon,
} from '@chakra-ui/react';
import { CopyInput, Table, TableRow } from '@fedimint/ui';
import { useConsensusPolling, useGuardianContext } from '../hooks';
import { GuardianRole, ServerStatus } from '../types';
import { getModuleParamsFromConfig } from '../utils/api';
import { useTranslation } from '@fedimint/utils';
import { ReactComponent as CopyIcon } from '../assets/svgs/copy.svg';

interface Props {
  next(): void;
}

export const ConnectGuardians: React.FC<Props> = ({ next }) => {
  const {
    state: { role, peers, numPeers, configGenParams },
    api,
  } = useGuardianContext();
  const { t } = useTranslation();

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
        <FormLabel>{t('connect_guardians.invite_guardians')}</FormLabel>
        <CopyInput
          value={process.env.REACT_APP_FM_CONFIG_API || ''}
          size='lg'
          buttonLeftIcon={<Icon as={CopyIcon} />}
        />
        <FormHelperText>
          {t('connect_guardians.connect_guardians_help')}
        </FormHelperText>
      </FormControl>
    );
  } else {
    // TODO: Consider making this more dynamic, work with unknown modules etc.
    const rows = [
      {
        label: 'Federation name',
        value: configGenParams.meta?.federation_name,
      },
      {
        label: 'Network',
        value: getModuleParamsFromConfig(configGenParams, 'wallet')?.consensus
          ?.network,
      },
      {
        label: 'Block confirmations',
        value: getModuleParamsFromConfig(configGenParams, 'wallet')?.consensus
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
          <Button onClick={handleApprove}>
            {t('connect_guardians.approve')}
          </Button>
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
            status:
              peers[i].status === ServerStatus.ReadyForConfigGen ? (
                <Tag colorScheme='green'>{t('connect_guardians.approved')}</Tag>
              ) : (
                <Tag colorScheme='orange'>{t('connect_guardians.pedning')}</Tag>
              ),
          }
        : {
            key: i,
            name: `Guardian ${i + 1}`,
            status: (
              <Tag colorScheme='gray'>{t('connect_guardians.not_joined')}</Tag>
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

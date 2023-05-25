import {
  Flex,
  Card,
  CardBody,
  CardHeader,
  Table,
  Tbody,
  Tr,
  Td,
  Thead,
  Th,
} from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { useGuardianContext } from '../hooks';
import { StatusResponse, Versions } from '../types';
import { useTranslation } from '@fedimint/utils';

export const FederationDashboard: React.FC = () => {
  const { api } = useGuardianContext();
  const { t } = useTranslation();
  const [versions, setVersions] = useState<Versions>();
  const [epochCount, setEpochCount] = useState<number>();
  const [status, setStatus] = useState<StatusResponse>();

  useEffect(() => {
    api.version().then(setVersions).catch(console.error);
    api.fetchEpochCount().then(setEpochCount).catch(console.error);
    api.status().then(setStatus).catch(console.error);
  }, [api]);

  const apiVersion = versions?.core.api.length
    ? `${versions.core.api[0].major}.${versions.core.api[0].minor}`
    : '';
  const consensusVersion =
    versions?.core.consensus !== undefined ? `${versions.core.consensus}` : '';

  return (
    <Flex gap={4}>
      <Card flex='1'>
        <CardHeader>{t('federation_dashboard.card_header')}</CardHeader>
        <CardBody>
          <Table>
            <Tbody>
              <Tr>
                <Td>{t('federation_dashboard.your_status')}</Td>
                <Td>{status?.server}</Td>
              </Tr>
              <Tr>
                <Td>{t('federation_dashboard.epoch_count')}</Td>
                <Td>{epochCount}</Td>
              </Tr>
              <Tr>
                <Td>{t('federation_dashboard.api_version')}</Td>
                <Td>{apiVersion}</Td>
              </Tr>
              <Tr>
                <Td>{t('federation_dashboard.consensus_version')}</Td>
                <Td>{consensusVersion}</Td>
              </Tr>
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      <Card flex='1'>
        <CardHeader>{t('federation_dashboard.peer_info')}</CardHeader>
        <CardBody>
          <Table>
            <Thead>
              <Tr>
                <Th>{t('federation_dashboard.name')}</Th>
                <Th>{t('federation_dashboard.status')}</Th>
              </Tr>
            </Thead>
            {status && (
              <Tbody>
                {Object.entries(status?.consensus.status_by_peer).map(
                  ([peerId, peerStatus]) => (
                    <Tr key={peerId}>
                      <Td>
                        {t('federation_dashboard.peer')} {peerId}
                      </Td>
                      <Td>{peerStatus.connection_status}</Td>
                    </Tr>
                  )
                )}
              </Tbody>
            )}
          </Table>
        </CardBody>
      </Card>
    </Flex>
  );
};

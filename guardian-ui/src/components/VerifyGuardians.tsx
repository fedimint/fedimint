import {
  Button,
  FormControl,
  FormLabel,
  FormHelperText,
  Icon,
  VStack,
  Heading,
  Text,
  Spinner,
  Input,
  Tag,
  useTheme,
} from '@chakra-ui/react';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { FormGroup } from './ui/FormGroup';
import { useGuardianContext } from '../hooks';
import { GuardianRole, Peer } from '../types';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { CopyInput } from './ui/CopyInput';
import { formatApiErrorMessage, getMyPeerId } from '../utils/api';
import { Table } from './ui/Table';

interface PeerWithHash {
  id: string;
  peer: Peer;
  hash: string;
}

interface Props {
  next(): void;
}

export const VerifyGuardians: React.FC<Props> = ({ next }) => {
  const {
    api,
    state: { role, numPeers },
  } = useGuardianContext();
  const theme = useTheme();
  const isHost = role === GuardianRole.Host;
  const [myHash, setMyHash] = useState('');
  const [peersWithHash, setPeersWithHash] = useState<PeerWithHash[]>();
  const [enteredHashes, setEnteredHashes] = useState<string[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string>();

  const isAllValid =
    peersWithHash &&
    peersWithHash.every(({ hash }, idx) => hash === enteredHashes[idx]);

  useEffect(() => {
    async function assembleHashInfo() {
      try {
        const [{ peers }, hashes] = await Promise.all([
          api.getConsensusConfigGenParams(),
          api.getVerifyConfigHash(),
        ]);

        const myPeerId = getMyPeerId(peers);
        if (!myPeerId) {
          throw new Error(
            'Unable to determine which peer you are. Please refresh and try again.'
          );
        }

        setMyHash(hashes[myPeerId]);
        setPeersWithHash(
          Object.entries(peers)
            .map(([id, peer]) => ({
              id,
              peer,
              hash: hashes[id],
            }))
            .filter((peer) => peer.id !== myPeerId)
        );
      } catch (err) {
        setError(formatApiErrorMessage(err));
      }
    }
    assembleHashInfo();
  }, [api]);

  const handleNext = useCallback(async () => {
    setIsStarting(true);
    try {
      await api.startConsensus();
      next();
    } catch (err) {
      setError(formatApiErrorMessage(err));
    }
    setIsStarting(false);
  }, [api]);

  // Host of one immediately skips this step.
  useEffect(() => {
    if (isHost && !numPeers) {
      handleNext();
    }
  }, [handleNext, numPeers]);

  const tableColumns = useMemo(
    () => [
      { key: 'name', heading: 'Name', width: '200px' },
      { key: 'status', heading: 'Status', width: '160px' },
      { key: 'hashInput', heading: 'Paste verification code' },
    ],
    []
  );

  const handleChangeHash = useCallback((value: string, index: number) => {
    setEnteredHashes((hashes) => {
      const newHashes = [...hashes];
      newHashes[index] = value;
      return newHashes;
    });
  }, []);

  const tableRows = useMemo(() => {
    if (!peersWithHash) return [];
    return peersWithHash.map(({ peer, hash }, idx) => {
      const value = enteredHashes[idx] || '';
      const isValid = Boolean(value && value === hash);
      const isError = Boolean(value && !isValid);
      return {
        key: peer.cert,
        name: (
          <Text maxWidth={200} isTruncated>
            {peer.name}
          </Text>
        ),
        status: isValid ? <Tag colorScheme='green'>Verified</Tag> : '',
        hashInput: (
          <FormControl isInvalid={isError}>
            <Input
              variant='filled'
              value={value}
              placeholder='Input code here'
              onChange={(ev) => handleChangeHash(ev.currentTarget.value, idx)}
              readOnly={isValid}
            />
          </FormControl>
        ),
      };
    });
  }, [peersWithHash, enteredHashes, handleChangeHash]);

  if (error) {
    return (
      <VStack gap={4}>
        <Heading size='sm'>Something went wrong.</Heading>
        <Text color={theme.colors.red[500]}>{error}</Text>
      </VStack>
    );
  } else if (!peersWithHash) {
    return <Spinner />;
  } else {
    return (
      <VStack gap={8} justify='start' align='start'>
        <FormGroup>
          <FormControl>
            <FormLabel>Your verification code</FormLabel>
            <CopyInput value={myHash} />
            <FormHelperText>
              Share this code with other guardians
            </FormHelperText>
          </FormControl>
        </FormGroup>
        <Table
          title='Guardian verification codes'
          description='Enter each Guardian’s verification codes below.'
          columns={tableColumns}
          rows={tableRows}
        />
        <div>
          <Button
            isDisabled={!isAllValid}
            isLoading={isStarting}
            onClick={isAllValid ? handleNext : undefined}
            leftIcon={<Icon as={ArrowRightIcon} />}
            mt={4}
          >
            Next
          </Button>
        </div>
      </VStack>
    );
  }
};

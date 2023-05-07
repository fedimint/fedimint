import {
  CircularProgress,
  CircularProgressLabel,
  Heading,
  Text,
  VStack,
  useTheme,
} from '@chakra-ui/react';
import React, { useEffect, useMemo, useState } from 'react';
import { useConsensusPolling, useGuardianContext } from '../hooks';
import { ServerStatus } from '../types';
import { formatApiErrorMessage } from '../utils/api';

interface Props {
  next(): void;
}

export const RunDKG: React.FC<Props> = ({ next }) => {
  const {
    api,
    state: { peers },
  } = useGuardianContext();
  const theme = useTheme();
  const [isWaitingForOthers, setIsWaitingForOthers] = useState(false);
  const [error, setError] = useState<string>();

  // Poll for peers and configGenParams while on this page.
  useConsensusPolling();

  // Keep trying to run DKG until it's finished, or we get an unexpected error.
  // "Cancel" the effect on re-run to prevent calling `runDkg` multiple times.
  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let canceled = false;
    const pollDkg = async () => {
      try {
        const status = await api.status();
        if (canceled) return;
        switch (status) {
          case ServerStatus.SharingConfigGenParams:
            await api.runDkg().catch((err) => {
              // If we timed out, np just try again
              if (err.code === -32002) return;
              throw err;
            });
            break;
          case ServerStatus.ReadyForConfigGen:
            setIsWaitingForOthers(true);
            break;
          case ServerStatus.VerifyingConfigs:
            next();
            break;
          case ServerStatus.ConfigGenFailed:
            setError(
              'Failed to run distributed key generation. Federation setup must be restarted.'
            );
            break;
          default:
            setError(`Not ready for DKG, your current status is "${status}"`);
        }
      } catch (err) {
        setError(formatApiErrorMessage(err));
      }
      timeout = setTimeout(pollDkg, 3000);
    };
    pollDkg();

    return () => {
      clearTimeout(timeout);
      canceled = true;
    };
  }, [next]);

  const progress = useMemo(() => {
    if (!peers.length) return 0;
    const peersWaiting = peers.filter(
      (p) => p.status === ServerStatus.ReadyForConfigGen
    );
    return Math.round((peersWaiting.length / peers.length) * 100);
  }, [peers]);

  return (
    <VStack gap={8} justify='center' align='center'>
      <CircularProgress
        isIndeterminate={!isWaitingForOthers}
        value={isWaitingForOthers ? progress : undefined}
        color={theme.colors.blue[400]}
        size='200px'
      >
        {isWaitingForOthers && (
          <CircularProgressLabel textStyle='sm'>
            {progress}%
          </CircularProgressLabel>
        )}
      </CircularProgress>
      {error ? (
        <>
          <Heading size='sm' color={theme.colors.red[500]}>
            Something went wrong.
          </Heading>
          <Text>{error}</Text>
        </>
      ) : (
        <Heading size='sm'>
          {isWaitingForOthers ? 'Waiting for peers...' : 'Generating codes...'}
        </Heading>
      )}
    </VStack>
  );
};

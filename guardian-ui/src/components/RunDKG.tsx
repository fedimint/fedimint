import {
  CircularProgress,
  Heading,
  Text,
  VStack,
  useTheme,
} from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { useGuardianContext } from '../hooks';

interface Props {
  next(): void;
}

export const RunDKG: React.FC<Props> = ({ next }) => {
  const { api } = useGuardianContext();
  const theme = useTheme();
  const [error, setError] = useState<string>();

  useEffect(() => {
    api
      .runDkg()
      .then(() => next())
      .catch((err) => {
        const message = err.message || err.toString();
        if (message === 'Dkg was already run') {
          next();
        } else {
          setError(message);
        }
      });
  }, [next]);

  return (
    <VStack gap={8} justify='center' align='center'>
      {error ? (
        <>
          <Heading color={theme.colors.red[500]}>Something went wrong.</Heading>
          <Text>{error}</Text>
        </>
      ) : (
        <>
          <CircularProgress isIndeterminate color='#23419F' size='200px' />
          <Heading>Generating codes...</Heading>
        </>
      )}
    </VStack>
  );
};

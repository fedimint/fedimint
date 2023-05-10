import React, { useEffect, useMemo, useState } from 'react';
import {
  ChakraProvider,
  Box,
  VStack,
  Spinner,
  Heading,
  Text,
  Center,
} from '@chakra-ui/react';
import { theme, Fonts } from './theme';
import { GuardianApi } from './GuardianApi';
import { GuardianProvider } from './GuardianContext';
import { Setup } from './components/Setup';
import { formatApiErrorMessage } from './utils/api';

export const App = React.memo(function App() {
  const api = useMemo(() => new GuardianApi(), []);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    api
      .connect()
      .then(() => {
        setIsConnected(true);
      })
      .catch((err) => {
        setError(formatApiErrorMessage(err));
      });
  }, [api]);

  return (
    <React.StrictMode>
      <Fonts />
      <ChakraProvider theme={theme}>
        <GuardianProvider api={api}>
          <Center>
            <Box
              maxW='960px'
              width='100%'
              mt={10}
              mb={10}
              mr={[2, 4, 6, 10]}
              ml={[2, 4, 6, 10]}
              p={5}
            >
              {isConnected ? (
                <Setup />
              ) : error ? (
                <Center>
                  <VStack>
                    <Heading>Something went wrong.</Heading>
                    <Text>{error}</Text>
                  </VStack>
                </Center>
              ) : (
                <Center>
                  <Box p={10}>
                    <Spinner size='xl' />
                  </Box>
                </Center>
              )}
            </Box>
          </Center>
        </GuardianProvider>
      </ChakraProvider>
    </React.StrictMode>
  );
});

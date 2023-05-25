import React, { useEffect, useMemo, useState } from 'react';
import { Box, VStack, Spinner, Heading, Text, Center } from '@chakra-ui/react';
import { theme, Fonts, SharedChakraProvider } from '@fedimint/ui';
import { GuardianApi } from './GuardianApi';
import { GuardianProvider } from './GuardianContext';
import { Setup } from './components/Setup';
import { formatApiErrorMessage } from './utils/api';
import { useTranslation } from '@fedimint/utils';

export const App = React.memo(function App() {
  const api = useMemo(() => new GuardianApi(), []);
  const { t } = useTranslation();
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
      <SharedChakraProvider theme={theme}>
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
                    <Heading>{t('app.error')}</Heading>
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
      </SharedChakraProvider>
    </React.StrictMode>
  );
});

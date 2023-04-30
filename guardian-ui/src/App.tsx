import React from 'react';
import { ChakraProvider } from '@chakra-ui/react';
import { theme, Fonts } from './theme';
import { GuardianApi } from './GuardianApi';
import { GuardianProvider } from './GuardianContext';
import { Setup } from './components/Setup';

export const App = React.memo(() => {
  const api = new GuardianApi();

  return (
    <React.StrictMode>
      <Fonts />
      <ChakraProvider theme={theme}>
        <GuardianProvider api={api}>
          <Setup />
        </GuardianProvider>
      </ChakraProvider>
    </React.StrictMode>
  );
});

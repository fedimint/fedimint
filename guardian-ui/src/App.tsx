import React from 'react';
import { ChakraProvider } from '@chakra-ui/react';
import { theme, Fonts } from './theme';
import { GuardianProvider } from './GuardianContext';
import { Setup } from './components/Setup';

export const App = React.memo(() => {
  return (
    <React.StrictMode>
      <Fonts />
      <ChakraProvider theme={theme}>
        <GuardianProvider>
          <Setup />
        </GuardianProvider>
      </ChakraProvider>
    </React.StrictMode>
  );
});

import React from 'react';
import { ChakraProvider, ChakraProviderProps } from '@chakra-ui/react';

/**
 * Shared chakra provider avails the exact same context
 * between components in @fedimint/ui and apps / packages that depend on these components
 */
export const SharedChakraProvider: React.FC<ChakraProviderProps> = ({
  theme,
  children,
}: ChakraProviderProps | any) => {
  return <ChakraProvider theme={theme}>{children}</ChakraProvider>;
};

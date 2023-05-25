import React from 'react';
import { VStack } from '@chakra-ui/react';

export const FormGroup: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => (
  <VStack gap={4} align='start' width='100%' maxWidth={320}>
    {children}
  </VStack>
);

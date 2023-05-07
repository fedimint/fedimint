import React, { useCallback, useState } from 'react';
import {
  Input,
  FormControl,
  FormLabel,
  Button,
  VStack,
  FormErrorMessage,
} from '@chakra-ui/react';
import { useGuardianContext } from '../hooks';
import { SETUP_ACTION_TYPE } from '../types';
import { formatApiErrorMessage } from '../utils/api';

export const Login: React.FC = () => {
  const { api, dispatch } = useGuardianContext();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string>();

  const handleSubmit = useCallback(
    async (ev: React.FormEvent) => {
      ev.preventDefault();
      try {
        const isValid = await api.testPassword(password);
        if (isValid) {
          dispatch({ type: SETUP_ACTION_TYPE.SET_PASSWORD, payload: password });
        } else {
          setError('Invalid password');
        }
      } catch (err: unknown) {
        console.error({ err });
        setError(formatApiErrorMessage(err));
      }
    },
    [api, password]
  );

  return (
    <form onSubmit={handleSubmit}>
      <VStack gap={2} align='start' justify='start'>
        <FormControl isInvalid={!!error}>
          <FormLabel>Password</FormLabel>
          <Input
            type='password'
            value={password}
            onChange={(ev) => setPassword(ev.currentTarget.value)}
          />
          {error && <FormErrorMessage>{error}</FormErrorMessage>}
        </FormControl>
        <Button type='submit'>Submit</Button>
      </VStack>
    </form>
  );
};

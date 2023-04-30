import {
  VStack,
  FormControl,
  FormLabel,
  FormHelperText,
  Input,
  Select,
  Flex,
  Icon,
  Heading,
  Button,
} from '@chakra-ui/react';
import React, { useState } from 'react';
import { useGuardianContext } from '../hooks';
import { GuardianRole, Network } from '../types';
import { ReactComponent as FedimintLogo } from '../assets/svgs/fedimint.svg';
import { ReactComponent as BitcoinLogo } from '../assets/svgs/bitcoin.svg';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';

interface Props {
  next(): void;
}

export const SetConfiguration: React.FC<Props> = ({ next }) => {
  const {
    state: { role },
  } = useGuardianContext();
  const isHost = role === GuardianRole.Host;
  const [guardianName, setGuardianName] = useState('');
  const [password, setPassword] = useState('');
  const [federationName, setFederationName] = useState('');
  const [numGuardians, setNumGuardians] = useState('');
  const [blockConfirmations, setBlockConfirmations] = useState('');
  const [network, setNetwork] = useState('');

  const isValidNumber = (value: string) => {
    const int = parseInt(value, 10);
    return int && !Number.isNaN(int);
  };

  let isValid: boolean;
  if (isHost) {
    isValid = Boolean(
      guardianName &&
        password &&
        federationName &&
        isValidNumber(numGuardians) &&
        isValidNumber(blockConfirmations) &&
        network
    );
  } else {
    isValid = Boolean(guardianName && password);
  }

  return (
    <VStack gap={8} justify='start' align='start'>
      <FormGroup>
        <FormControl>
          <FormLabel>Guardian name</FormLabel>
          <Input
            value={guardianName}
            onChange={(ev) => setGuardianName(ev.currentTarget.value)}
          />
          <FormHelperText>
            This name will be shown to other Guardians
          </FormHelperText>
        </FormControl>
        <FormControl>
          <FormLabel>Admin password</FormLabel>
          <Input
            type='password'
            value={password}
            onChange={(ev) => setPassword(ev.currentTarget.value)}
          />
          <FormHelperText>
            You'll need this every time you visit this page.
          </FormHelperText>
        </FormControl>
      </FormGroup>
      {isHost && (
        <>
          <FormGroup>
            <FormGroupHeading icon={FedimintLogo} title='Federation settings' />
            <FormControl>
              <FormLabel>Federation name</FormLabel>
              <Input
                value={federationName}
                onChange={(ev) => setFederationName(ev.currentTarget.value)}
              />
            </FormControl>
            <FormControl>
              <FormLabel>Number of guardians</FormLabel>
              <Input
                type='number'
                min={1}
                value={numGuardians}
                onChange={(ev) => setNumGuardians(ev.currentTarget.value)}
              />
              <FormHelperText>This cannot be changed later.</FormHelperText>
            </FormControl>
          </FormGroup>

          <FormGroup>
            <FormGroupHeading icon={BitcoinLogo} title='Bitcoin settings' />
            <FormControl>
              <FormLabel>Block confirmations</FormLabel>
              <Input
                type='number'
                min={1}
                value={blockConfirmations}
                onChange={(ev) => setBlockConfirmations(ev.currentTarget.value)}
              />
              <FormHelperText>
                How many block confirmations needed before confirming?
              </FormHelperText>
            </FormControl>
            <FormControl>
              <FormLabel>Bitcoin network</FormLabel>
              <Select
                placeholder='Select a network'
                value={network}
                onChange={(ev) => setNetwork(ev.currentTarget.value)}
              >
                {Object.entries(Network).map(([label, value]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </FormControl>
          </FormGroup>
        </>
      )}
      <div>
        <Button
          isDisabled={!isValid}
          onClick={isValid ? next : undefined}
          leftIcon={<Icon as={ArrowRightIcon} />}
          mt={4}
        >
          Next
        </Button>
      </div>
    </VStack>
  );
};

const FormGroup: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <VStack gap={4} align='start' width='100%' maxWidth={320}>
    {children}
  </VStack>
);

const FormGroupHeading: React.FC<{
  icon: React.FunctionComponent<React.SVGAttributes<SVGElement>>;
  title: React.ReactNode;
}> = ({ icon, title }) => (
  <Flex align='center' justify='start' mb={-3}>
    <Icon width='20px' height='20px' mr={2} as={icon} />
    <Heading fontSize='md' lineHeight='20px' fontWeight='700'>
      {title}
    </Heading>
  </Flex>
);

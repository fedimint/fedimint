import {
  VStack,
  FormControl,
  FormLabel,
  FormHelperText,
  Input,
  Select,
  Icon,
  Button,
} from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { useGuardianContext } from '../hooks';
import { GuardianRole, Network } from '../types';
import { ReactComponent as FedimintLogo } from '../assets/svgs/fedimint.svg';
import { ReactComponent as BitcoinLogo } from '../assets/svgs/bitcoin.svg';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { FormGroup } from './ui/FormGroup';
import { FormGroupHeading } from './ui/FormGroupHeading';

interface Props {
  next(): void;
}

export const SetConfiguration: React.FC<Props> = ({ next }) => {
  const {
    state: {
      role,
      configGenParams,
      myName: stateMyName,
      password: statePassword,
      numPeers: stateNumPeers,
    },
    api,
    submitConfiguration,
  } = useGuardianContext();
  const isHost = role === GuardianRole.Host;
  const [myName, setMyName] = useState(stateMyName);
  const [password, setPassword] = useState(statePassword);
  const [federationName, setFederationName] = useState(
    configGenParams?.meta.federation_name || ''
  );
  const [numPeers, setNumPeers] = useState(
    stateNumPeers ? stateNumPeers.toString() : ''
  );
  const [blockConfirmations, setBlockConfirmations] = useState(
    configGenParams?.modules?.wallet?.finality_delay?.toString() || ''
  );
  const [network, setNetwork] = useState(
    configGenParams?.modules?.wallet?.network || ''
  );
  const [mintAmounts, setMintAmounts] = useState<number[]>([]);

  useEffect(() => {
    if (configGenParams === null) {
      api
        .getDefaultConfigGenParams()
        .then((params) => {
          setFederationName(params.meta.federation_name);
          setBlockConfirmations(
            params.modules.wallet.finality_delay.toString()
          );
          setNetwork(params.modules.wallet.network);
          setMintAmounts(params.modules.mint.mint_amounts);
        })
        .catch((err) => {
          console.error(err);
        });
    }
  }, [configGenParams]);

  // Update password when updated from state
  useEffect(() => {
    setPassword(statePassword);
  }, [statePassword]);

  const isValidNumber = (value: string) => {
    const int = parseInt(value, 10);
    return int && !Number.isNaN(int);
  };

  const isValid: boolean = isHost
    ? Boolean(
        myName &&
          password &&
          federationName &&
          isValidNumber(numPeers) &&
          isValidNumber(blockConfirmations) &&
          network
      )
    : Boolean(myName && password);

  const handleNext = async () => {
    try {
      await submitConfiguration({
        password,
        myName,
        numPeers: parseInt(numPeers, 10),
        config: {
          meta: { federation_name: federationName },
          modules: {
            mint: {
              mint_amounts: mintAmounts,
            },
            wallet: {
              finality_delay: parseInt(blockConfirmations, 10),
              network: network as Network,
            },
          },
        },
      });
      next();
    } catch (err) {
      // FIXME: Handle error and show error UI
      console.error(err);
    }
  };

  return (
    <VStack gap={8} justify='start' align='start'>
      <FormGroup>
        <FormControl>
          <FormLabel>Guardian name</FormLabel>
          <Input
            value={myName}
            onChange={(ev) => setMyName(ev.currentTarget.value)}
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
            isDisabled={!!statePassword}
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
                value={numPeers}
                onChange={(ev) => setNumPeers(ev.currentTarget.value)}
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
                onChange={(ev) => {
                  const value = ev.currentTarget.value;
                  isValidNumber(value) && setBlockConfirmations(value);
                }}
              />
              <FormHelperText>
                How many block confirmations needed before confirming?
              </FormHelperText>
            </FormControl>
            <FormControl>
              <FormLabel>Bitcoin network</FormLabel>
              <Select
                placeholder='Select a network'
                value={network !== null ? network : ''}
                onChange={(ev) => {
                  const value = ev.currentTarget.value;
                  setNetwork(value as unknown as Network);
                }}
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
          onClick={isValid ? handleNext : undefined}
          leftIcon={<Icon as={ArrowRightIcon} />}
          mt={4}
        >
          Next
        </Button>
      </div>
    </VStack>
  );
};

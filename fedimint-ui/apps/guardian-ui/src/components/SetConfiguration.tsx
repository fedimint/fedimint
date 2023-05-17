import React, { useEffect, useState } from 'react';
import {
  VStack,
  FormControl,
  FormLabel,
  FormHelperText,
  Input,
  Select,
  Icon,
  Button,
  Text,
  useTheme,
} from '@chakra-ui/react';
import { FormGroup, FormGroupHeading } from '@fedimint/ui';
import { useGuardianContext } from '../hooks';
import { BitcoinRpc, ConfigGenParams, GuardianRole, Network } from '../types';
import { ReactComponent as FedimintLogo } from '../assets/svgs/fedimint.svg';
import { ReactComponent as BitcoinLogo } from '../assets/svgs/bitcoin.svg';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { formatApiErrorMessage, getModuleParamsFromConfig } from '../utils/api';

interface Props {
  next: () => void;
}

export const SetConfiguration: React.FC<Props> = ({ next }: Props) => {
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
  const theme = useTheme();
  const isHost = role === GuardianRole.Host;
  const [myName, setMyName] = useState(stateMyName);
  const [password, setPassword] = useState(statePassword);
  const [hostServerUrl, setHostServerUrl] = useState('');
  const [numPeers, setNumPeers] = useState(
    stateNumPeers ? stateNumPeers.toString() : ''
  );
  const [federationName, setFederationName] = useState('');
  const [blockConfirmations, setBlockConfirmations] = useState('');
  const [network, setNetwork] = useState('');
  const [bitcoinRpc, setBitcoinRpc] = useState<BitcoinRpc>({
    kind: '',
    url: '',
  });
  const [mintAmounts, setMintAmounts] = useState<number[]>([]);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const initStateFromParams = (params: ConfigGenParams) => {
      setFederationName(params.meta?.federation_name || '');

      setMintAmounts(
        getModuleParamsFromConfig(params, 'mint')?.consensus?.mint_amounts ||
          mintAmounts
      );

      const walletModule = getModuleParamsFromConfig(params, 'wallet');

      if (walletModule) {
        setBlockConfirmations(
          walletModule.consensus?.finality_delay?.toString() ||
            blockConfirmations
        );
        setNetwork(walletModule.consensus?.network.toString() || network);
        setBitcoinRpc(walletModule.local?.bitcoin_rpc || bitcoinRpc);
      }
    };

    if (configGenParams === null) {
      api
        .getDefaultConfigGenParams()
        .then(initStateFromParams)
        .catch((err) => {
          console.error(err);
        });
    } else {
      initStateFromParams(configGenParams);
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
    : Boolean(myName && password && hostServerUrl);

  const handleNext = async () => {
    setError(undefined);
    try {
      if (isHost) {
        // Hosts set their own connection name
        // - They should submit both their local and the consensus config gen params.
        await submitConfiguration({
          myName,
          password,
          configs: {
            numPeers: parseInt(numPeers, 10),
            meta: { federation_name: federationName },
            modules: {
              // TODO: figure out way to not hard-code modules here
              1: [
                'mint',
                { consensus: { mint_amounts: mintAmounts }, local: {} },
              ],
              2: [
                'wallet',
                {
                  consensus: {
                    finality_delay: parseInt(blockConfirmations, 10),
                    network: network as Network,
                  },
                  local: {
                    bitcoin_rpc: bitcoinRpc,
                  },
                },
              ],
              3: [
                'ln',
                { local: { bitcoin_rpc: bitcoinRpc } },
              ],
            },
          },
        });
      } else {
        // Followers set their own connection name, and hosts server URL to connect to.
        // - They should submit ONLY their local config gen params
        await submitConfiguration({
          myName,
          password,
          configs: {
            hostServerUrl,
            meta: {},
            modules: {
              // TODO: figure out way to not hard-code modules here
              2: [
                'wallet',
                {
                  local: {
                    bitcoin_rpc: bitcoinRpc,
                  },
                },
              ],
              3: [
                'ln',
                { local: { bitcoin_rpc: bitcoinRpc } },
              ],
            },
          },
        });
      }
      next();
    } catch (err) {
      setError(formatApiErrorMessage(err));
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
            {"You'll need this every time you visit this page."}
          </FormHelperText>
        </FormControl>
        {!isHost && (
          <FormControl>
            <FormLabel>Join Federation link</FormLabel>
            <Input
              value={hostServerUrl}
              onChange={(ev) => setHostServerUrl(ev.currentTarget.value)}
              placeholder='ws://...'
            />
            <FormHelperText>
              Ask the person who created the Federation for a link, and paste it
              here.
            </FormHelperText>
          </FormControl>
        )}
      </FormGroup>
      <>
        {isHost && (
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
        )}
        <FormGroup>
          <FormGroupHeading icon={BitcoinLogo} title='Bitcoin settings' />
          {isHost && (
            <>
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
            </>
          )}
          <FormControl>
            <FormLabel>Bitcoin RPC</FormLabel>
            <Input
              value={bitcoinRpc.url}
              onChange={(ev) => {
                setBitcoinRpc({ ...bitcoinRpc, url: ev.currentTarget.value });
              }}
            />
            <FormHelperText>
              Locally configured Bitcoin RPC address
            </FormHelperText>
          </FormControl>
        </FormGroup>
      </>
      {error && (
        <Text color={theme.colors.red[500]} mt={4}>
          {error}
        </Text>
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

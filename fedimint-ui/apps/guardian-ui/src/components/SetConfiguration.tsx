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
  FormErrorMessage,
  NumberInput,
  NumberInputField,
  NumberIncrementStepper,
  NumberDecrementStepper,
  NumberInputStepper,
} from '@chakra-ui/react';
import { FormGroup, FormGroupHeading } from '@fedimint/ui';
import { useGuardianContext } from '../hooks';
import { BitcoinRpc, ConfigGenParams, GuardianRole, Network } from '../types';
import { ReactComponent as FedimintLogo } from '../assets/svgs/fedimint.svg';
import { ReactComponent as BitcoinLogo } from '../assets/svgs/bitcoin.svg';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { formatApiErrorMessage, getModuleParamsFromConfig } from '../utils/api';
import { useTranslation } from '@fedimint/utils';

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
  const { t } = useTranslation();
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
                {
                  consensus: { network: network as Network },
                  local: { bitcoin_rpc: bitcoinRpc },
                },
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
              3: ['ln', { local: { bitcoin_rpc: bitcoinRpc } }],
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
          <FormLabel>{t('set_config.guardian_name')}</FormLabel>
          <Input
            value={myName}
            onChange={(ev) => setMyName(ev.currentTarget.value)}
          />
          <FormHelperText>{t('set_config.guardian_name_help')}</FormHelperText>
        </FormControl>
        <FormControl>
          <FormLabel>{t('set_config.admin_password')}</FormLabel>
          <Input
            type='password'
            value={password}
            onChange={(ev) => setPassword(ev.currentTarget.value)}
            isDisabled={!!statePassword}
          />
          <FormHelperText>{t('set_config.admin_password_help')}</FormHelperText>
        </FormControl>
        {!isHost && (
          <FormControl>
            <FormLabel>{t('set_config.join_federation')}</FormLabel>
            <Input
              value={hostServerUrl}
              onChange={(ev) => setHostServerUrl(ev.currentTarget.value)}
              placeholder='ws://...'
            />
            <FormHelperText>
              {t('set_config.join_federation_help')}
            </FormHelperText>
          </FormControl>
        )}
      </FormGroup>
      <>
        {isHost && (
          <FormGroup>
            <FormGroupHeading
              icon={FedimintLogo}
              title={`${t('set_config.federation_settings')}`}
            />
            <FormControl>
              <FormLabel>{t('set_config.federation_name')}</FormLabel>
              <Input
                value={federationName}
                onChange={(ev) => setFederationName(ev.currentTarget.value)}
              />
            </FormControl>
            <FormControl>
              <FormLabel>{t('set_config.guardian_number')}</FormLabel>
              <Input
                type='number'
                min={1}
                value={numPeers}
                onChange={(ev) => setNumPeers(ev.currentTarget.value)}
              />
              <FormHelperText>
                {t('set_config.guardian_number_help')}
              </FormHelperText>
            </FormControl>
          </FormGroup>
        )}
        <FormGroup>
          <FormGroupHeading icon={BitcoinLogo} title='Bitcoin settings' />
          {isHost && (
            <>
              <FormControl isInvalid={!isValidNumber(blockConfirmations)}>
                <FormLabel>{t('set_config.block_confirmations')}</FormLabel>
                <NumberInput
                  min={1}
                  max={200}
                  value={blockConfirmations}
                  onChange={(value) => {
                    setBlockConfirmations(value);
                  }}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <FormErrorMessage>
                  {t('set_config.error_valid_number')}
                </FormErrorMessage>
                <FormHelperText>
                  {t('set_config.block_confirmations_help')}
                </FormHelperText>
              </FormControl>
              <FormControl>
                <FormLabel>{t('set_config.bitcoin_network')}</FormLabel>
                <Select
                  placeholder={`${t('set_config.select_network')}`}
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
            <FormLabel>{t('set_config.bitcoin_rpc')}</FormLabel>
            <Input
              value={bitcoinRpc.url}
              onChange={(ev) => {
                setBitcoinRpc({ ...bitcoinRpc, url: ev.currentTarget.value });
              }}
            />
            <FormHelperText>{t('set_config.set_rpc_help')}</FormHelperText>
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
          {t('common.next')}
        </Button>
      </div>
    </VStack>
  );
};

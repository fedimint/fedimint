import React, { useEffect, useState } from 'react';
import {
  TabPanel,
  Stack,
  Card,
  CardBody,
  CardFooter,
  Image,
  Heading,
  Text,
  Spacer,
  Flex,
  Progress,
  Badge,
  Box,
  Button,
} from '@chakra-ui/react';
import { QRCodeSVG } from 'qrcode.react';
import { TransactionStatus } from '../ExplorerApi';
import { ApiContext, TabHeader } from '.';

export const DepositTabHeader = (): JSX.Element => {
  return <TabHeader>Deposit</TabHeader>;
};

const truncateStringFormat = (arg = ''): string => {
  return `${arg.substring(0, 15)}......${arg.substring(
    arg.length,
    arg.length - 15
  )}`;
};

export interface DepositTabProps {
  federationId: string;
  active: boolean;
}

export const DepositTab = React.memo(function DepositTab({
  federationId,
  active,
}: DepositTabProps): JSX.Element {
  const { gateway, explorer } = React.useContext(ApiContext);

  const [address, setAddress] = useState<string>('');
  const [txStatus, setTxStatus] = useState<TransactionStatus | null>(null);

  useEffect(() => {
    !address &&
      gateway.fetchAddress(federationId).then((newAddress) => {
        setAddress(newAddress);
      });
  }, []);

  useEffect(() => {
    if (!address || !active) return;

    const observeMempool = async (timer?: NodeJS.Timer) => {
      try {
        const txStatus = await explorer.watchAddressForTransaction(address);

        if (txStatus) {
          setTxStatus(txStatus);

          console.log(
            'Detected a deposit transaction to the address: ',
            address
          );
          timer && clearInterval(timer);
        }
      } catch (e) {
        console.log(e);
        // TODO: Show error UI
      }
    };

    // Watch for a transaction to be sent to the address
    const timer = setInterval(async () => {
      await observeMempool(timer);
    }, 5000);

    // We probably don't need to immediately check mempool for transaction
    // observeMempool(timer);

    return () => clearInterval(timer);
  }, [explorer, address, active]);

  const getDepositCardProps = (): DepositCardProps => {
    if (txStatus) {
      return {
        content: (
          <WatchTransaction
            {...{
              address,
              txStatus,
              confirmationsRequired: 3,
              federationId: 'test',
            }}
          />
        ),
        actions: [
          {
            label: 'View Transaction',
            onClick: () => window.open(txStatus.viewTransactionUrl, '_blank'),
          },
        ],
        infographic: {
          imgUrl:
            'https://www.maxpixel.net/static/photo/1x/Bitcoin-Logo-Bitcoin-Icon-Bitcoin-Btc-Icon-Currency-6219384.png',
          altText: 'Pending bitcoin transaction',
        },
      };
    }

    return {
      content: <ShowDepositAddress address={address} />,
      actions: [
        {
          label: 'Share Address',
          // TODO: Initiate share address
          onClick: () => console.log(address),
        },
        {
          label: 'Copy Address',
          // TODO: Copy address to clipboard
          onClick: () => console.log(address),
        },
      ],
      infographic: {
        qrStr: address,
      },
    };
  };

  return (
    <TabPanel pl='8px' pr='8px'>
      <DepositCard {...getDepositCardProps()} />
    </TabPanel>
  );
});

interface DepositCardProps {
  content: JSX.Element;
  actions?: DepositCardAction[];
  infographic?: ImageRenderer | QRCodeRenderer;
}

interface DepositCardAction {
  label: string;
  onClick: () => void;
}

interface ImageRenderer {
  imgUrl: string;
  altText: string;
}

interface QRCodeRenderer {
  qrStr: string;
}

const isQrCodeRenderer = (
  renderer: ImageRenderer | QRCodeRenderer
): renderer is QRCodeRenderer => {
  return 'qrStr' in renderer;
};

export const DepositCard = React.memo(function DepositCard(
  props: DepositCardProps
): JSX.Element {
  const { content, actions, infographic } = props;

  return (
    <Card overflow='hidden' variant='unstyled'>
      <Stack alignItems='center' flexDir={{ base: 'column', md: 'row' }}>
        <CardBody>{content}</CardBody>
        {infographic && (
          <>
            {isQrCodeRenderer(infographic) ? (
              <Box width='250px' height='100%'>
                <QRCodeSVG
                  height='100%'
                  width='100%'
                  value={infographic.qrStr}
                />
              </Box>
            ) : (
              <Image
                objectFit='cover'
                maxW={{ base: '200px', sm: '200px' }}
                src={infographic.imgUrl}
                alt={infographic.altText}
              />
            )}
          </>
        )}
      </Stack>
      <CardFooter
        justifyContent={{ base: 'space-between', md: 'normal' }}
        pt={{ base: 6, md: 2, lg: 2 }}
        gap='6'
      >
        {actions?.map((action: DepositCardAction, i: number) => {
          return (
            <Button
              fontSize={{ base: '12px', md: '13px', lg: '16px' }}
              onClick={action.onClick}
              key={i}
              width={{ base: '100%', md: 'fit-content' }}
            >
              {action.label}
            </Button>
          );
        })}
      </CardFooter>
    </Card>
  );
});

interface ShowDepositAddressProps {
  address: string;
}

const ShowDepositAddress = ({
  address,
}: ShowDepositAddressProps): JSX.Element => {
  return (
    <>
      <Heading
        fontWeight='500'
        fontSize={{ base: '22', md: '24' }}
        color='#1A202C'
      >
        Bitcoin Deposit to Federation
      </Heading>

      <Text maxW='sm' py='3'>
        Please pay to the address address shown to deposit funds into this
        federation You can scan the QR code to pay.
      </Text>
      <Text py='1'></Text>
      <Flex
        flexDir={{ base: 'column', md: 'row' }}
        alignItems={{ base: 'left', md: 'center' }}
        mb={4}
      >
        <Text fontSize='lg' fontWeight='500' color='#1A202C' mr={2}>
          Address:
        </Text>
        <Text fontSize='lg'>{truncateStringFormat(address)}</Text>
      </Flex>
    </>
  );
};

interface WatchTransactionProps {
  address: string;
  txStatus: TransactionStatus;
  confirmationsRequired: number;
  federationId: string;
}

const WatchTransaction = ({
  address,
  txStatus,
  confirmationsRequired,
  federationId,
}: WatchTransactionProps) => {
  const { gateway, explorer } = React.useContext(ApiContext);

  const [status, setStatus] = useState(txStatus);

  useEffect(() => {
    const obseTxSequence = async (timer?: NodeJS.Timer) => {
      try {
        const txStatus = await explorer.watchTransactionStatus(
          address,
          status.transactionId
        );

        if (txStatus.confirmations === confirmationsRequired) {
          const proof = await explorer.fetchTransactionProof(
            status.transactionId
          );

          // Automatically complete the deposit to federation
          // TODO: Call to completeDeposit should be automated.
          // once all the required data is available, complete the deposit without requiring user interaction.
          const fmTxId = await gateway.completeDeposit(
            federationId,
            proof.transactionOutProof,
            proof.transactionHash
          );

          console.log('Fedimint Transaction ID: ', fmTxId);
          timer && clearInterval(timer);
        }

        setStatus(txStatus);
      } catch (e) {
        console.log(e);
        // TODO: Show error UI
      }
    };

    const timer = setInterval(async () => {
      await obseTxSequence(timer);
    }, 10000);

    obseTxSequence(timer);

    return () => clearInterval(timer);
  }, []);

  return (
    <>
      <Heading
        fontWeight='500'
        fontSize={{ base: '22', md: '24' }}
        color='#1A202C'
      >
        Bitcoin Deposit
      </Heading>
      <Flex align='center' mt={3}>
        <Text fontSize='lg' mr={2}>
          Amount:
        </Text>
        <Text fontSize='lg' fontWeight='bold'>
          {status.amount_btc} BTC
        </Text>
      </Flex>
      <Flex alignItems='center' gap={1}>
        <Flex
          flexDir={{ base: 'column', md: 'row' }}
          alignItems={{ base: 'left', md: 'center' }}
          mt={4}
        >
          <Text fontSize='lg' fontWeight='500' color='#1A202C' mr={2}>
            Confirmations:
          </Text>
          <Text>
            {status.confirmations} / {confirmationsRequired} required
          </Text>
        </Flex>
        <Spacer />
        <Badge
          colorScheme={status.status === 'pending' ? 'red' : 'orange'}
          variant='outline'
          mb={-4}
        >
          {status.status}
        </Badge>
      </Flex>
      <Progress
        value={(100 * status.confirmations) / confirmationsRequired}
        size='xs'
        colorScheme='orange'
        hasStripe
        mb={2}
      />
      <Flex
        flexDir={{ base: 'column', md: 'row' }}
        alignItems={{ base: 'left', md: 'center' }}
        mb={4}
      >
        <Text fontSize='lg' fontWeight='500' color='#1A202C' mr={2}>
          Receiving Addr:
        </Text>
        <Text> {truncateStringFormat(address)}</Text>
      </Flex>
      <Flex
        flexDir={{ base: 'column', md: 'row' }}
        alignItems={{ base: 'left', md: 'center' }}
        mb={4}
      >
        <Text fontSize='lg' fontWeight='500' color='#1A202C' mr={2}>
          Transaction ID:
        </Text>
        <Text> {truncateStringFormat(status.transactionId)}</Text>
      </Flex>
    </>
  );
};

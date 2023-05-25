import { Federation } from '../federation.types';
import { GatewayInfo, Mintgate } from './Mintgate';

/* eslint-disable @typescript-eslint/no-unused-vars */

// MockMintgate is a mock implementation of the Mintgate API
export class MockMintgate implements Mintgate {
  fetchInfo = async (): Promise<GatewayInfo> => {
    return {
      federations: [
        {
          federation_id: 'Hals_trusty_mint',
          mint_pubkey:
            '4222d0e6f9f4e0a9d471c81b3ee454032cddc8590a9aebf43332bb2d3ecb976c',
          details: {
            description: 'Hals Trusty Mint',
            date_created: '2018-01-01T00:00:00Z',
            name: 'Hals_trusty_mint',
            url: '',
            active: true,
          },
        },

        {
          federation_id: 'FTX_yield_gen',
          mint_pubkey:
            'c679bce3d2bb23334fbea9a0958cddc230454ee3b18c174d9a0e4f9f6e0d2224',
          details: {
            description: 'FTX yield generator',
            date_created: '2019-01-01T00:00:00Z',
            name: 'FTX_yield_gen',
            url: '',
            active: true,
          },
        },

        {
          federation_id: 'Qala_devs',
          mint_pubkey:
            '1d2eb31bb4c307b466e1a7c910693bc5754799ec705b14f760e74d5d4968acf9',
          details: {
            description: 'Qala_devs stacking sats',
            date_created: '2020-01-01T00:00:00Z',
            name: 'Qala_devs',
            url: '',
            active: false,
          },
        },
      ],
      version_hash: 'f876d12a78df7d4ef5b3a4913590ded6bfe5c3b1',
    };
  };

  fetchAddress = async (): Promise<string> => {
    // Use IP's bitcoin address as a mock
    return 'bc1qgf60crqtlxn7279tgh8lsxzagmu97cyuwtykxwv026s9hwg427fsjvw7uz';
  };

  connectFederation = async (_connectInfo: string): Promise<Federation> => {
    // TODO: autogenerate mock names
    const federation_id = 'mock_federation';
    // TODO: autogenerate mock pubkeys
    const mint_pubkey =
      '4222d0e6f9f4e0a9d471c81b3ee454032cddc8590a9aebf43332bb2d3ecb976c';

    return Promise.resolve({
      federation_id,
      mint_pubkey,
      details: {
        description: 'Newly connected federation mock',
        date_created: Date.now().toString(),
        name: 'mock_federation',
        url: '',
        active: true,
      },
    });
  };

  completeDeposit = async (
    _federationId: string,
    _txOutProof: string,
    _tx: string
  ): Promise<string> => {
    return Promise.resolve('mock_txid');
  };

  requestWithdrawal = async (
    _federationId: string,
    _amountSat: number,
    _address: string
  ): Promise<string> => {
    return Promise.resolve(
      'de3d5bf1e3c1b3be2a1e025825f751629390ad60c8f91723e330f2356d99c59b'
    );
  };
}

/* eslint-enable @typescript-eslint/no-unused-vars */

import { GatewayInfo, Federation } from './types';

// GatewayApi is an API to interact with the Gateway server
interface ApiInterface {
  fetchInfo: () => Promise<GatewayInfo>;
  fetchAddress: (federationId: string) => Promise<string>;
  connectFederation: (connectInfo: string) => Promise<Federation>;
  /**
   * Complete a deposit to a federation served by the Gateway
   * @param federationId id of the federation to deposit to
   * @param txOutProof transaction out proof for the deposit made to address previously sourced from federation via fetchAddress
   * @param tx transaction hash for the deposit made to address previously sourced from federation via fetchAddress
   * @returns `TransactionId` from the Fedimint federation
   */
  completeDeposit: (
    federationId: string,
    txOutProof: string,
    tx: string
  ) => Promise<string>;

  /**
   *  Request a withdrawal from a fedration served by the Gateway
   * @param federationId  id of the federation to withdraw from
   * @param amountSat the amount in satoshis to be withdrawn from the federation
   * @param address the bitcoin address to withdraw to
   * @returns `TransactionId` from the Fedimint federation
   */
  requestWithdrawal: (
    federationId: string,
    amountSat: number,
    address: string
  ) => Promise<string>;
}

// GatewayApi is an implementation of the ApiInterface
export class GatewayApi implements ApiInterface {
  private baseUrl: string | undefined = process.env.REACT_APP_FM_GATEWAY_API;
  private password = process.env.REACT_APP_FM_GATEWAY_PASSWORD || '';

  fetchInfo = async (): Promise<GatewayInfo> => {
    try {
      const res: Response = await fetch(`${this.baseUrl}/info`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.password}`,
        },
        body: JSON.stringify({}),
      });

      if (res.ok) {
        const info: GatewayInfo = await res.json();
        return Promise.resolve(info);
      }

      throw responseToError('Fetching gateway info', res);
    } catch (err) {
      return Promise.reject(err);
    }
  };

  fetchAddress = async (federationId: string): Promise<string> => {
    try {
      const res: Response = await fetch(`${this.baseUrl}/address`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.password}`,
        },
        body: JSON.stringify({
          federation_id: federationId,
        }),
      });

      if (res.ok) {
        const address: string = await res.text();
        return Promise.resolve(address);
      }

      throw responseToError('fetching federation address', res);
    } catch (err) {
      return Promise.reject(err);
    }
  };

  connectFederation = async (_connectInfo: string): Promise<Federation> => {
    throw new Error('Not implemented');
  };

  completeDeposit = async (
    _federationId: string,
    _txOutProof: string,
    _tx: string
  ): Promise<string> => {
    throw new Error('Not implemented');
  };

  requestWithdrawal = async (
    _federationId: string,
    _amountSat: number,
    _address: string
  ): Promise<string> => {
    throw new Error('Not implemented');
  };
}

const responseToError = (scenario: string, res: Response): Error => {
  return new Error(
    `${scenario} \nStatus : ${res.status} \nReason : ${res.statusText}\n`
  );
};

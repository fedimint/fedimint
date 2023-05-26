import { Federation } from './federation.types';

// GatewayApi is an API to interact with the Gateway server
interface ApiInterface {
  fetchInfo: () => Promise<GatewayInfo>;
  fetchAddress: () => Promise<string>;
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

// GatewayInfo is the information returned by the Gateway server
export interface GatewayInfo {
  version_hash: string;
  federations: Federation[];
}

/** TransactionId of a fedimint federation */
export type TransactionId = string;

// GatewayApi is an implementation of the ApiInterface
export class GatewayApi implements ApiInterface {
  private gatewayUrl: string | undefined = process.env.REACT_APP_FM_GATEWAY_API;

  fetchInfo = async (): Promise<GatewayInfo> => {
    throw new Error('Not implemented');
  };

  fetchAddress = (): Promise<string> => {
    throw new Error('Not implemented');
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

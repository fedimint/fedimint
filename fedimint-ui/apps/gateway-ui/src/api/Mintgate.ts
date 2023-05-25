import { Federation } from '../federation.types';

// Mintgate is an API to interact with the Gateway server
export interface Mintgate {
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

// NullGatewayInfo is a placeholder for when the GatewayInfo is not yet loaded
export const NullGatewayInfo: GatewayInfo = {
  version_hash: '',
  federations: [],
};

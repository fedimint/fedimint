export interface Federation {
  federation_id: string;
  registration: object;
  mint_pubkey: string;
}

export interface GatewayInfo {
  federations: Federation[];
  fees: {
    base_msat: number;
    proportional_millionths: number;
  };
  lightning_alias: string;
  lightning_pub_key: string;
  version_hash: string;
}

export type TransactionId = string;

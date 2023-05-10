export interface Federation {
	federation_id: string;
	mint_pubkey: string;
	details: FederationDetails;
}

export interface FederationDetails {
	name: string;
	description: string;
	url?: string;
	date_created: string;
	active: boolean;
}

export enum Sort {
	Ascending,
	Descending,
	Date,
}

export type Filter = undefined | boolean;

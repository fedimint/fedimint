import React, { useState } from 'react';
import { Box, Collapse, HStack } from '@chakra-ui/react';
import { Federation } from '../federation.types';
import { ApiContext } from './ApiProvider';
import { Button } from './Button';
import { Input } from './Input';

export type ConnectFederationProps = {
	isOpen: boolean;
	renderConnectedFedCallback: (federation: Federation) => void;
};

interface FedConnectInfo {
	value: string;
	isValid: boolean;
}

export const ConnectFederation = (connect: ConnectFederationProps) => {
	const { mintgate } = React.useContext(ApiContext);

	const [connectInfo, setConnectInfo] = useState<FedConnectInfo>({
		value: '',
		isValid: false,
	});

	const handleInputString = (event: React.ChangeEvent<HTMLInputElement>) => {
		event.preventDefault();
		const { value } = event.target;

		try {
			let parsed = JSON.parse(value);

			if (typeof parsed === 'string') {
				// Bug: why would we need a second pass at parsing json string?
				parsed = JSON.parse(parsed);
			}

			const isValid =
				Object.prototype.hasOwnProperty.call(parsed, 'members') &&
				parsed['members'].length > 0 &&
				parsed['members'].every((member: [number, string]) => {
					return (
						member.length === 2 &&
						typeof member[0] === 'number' &&
						typeof member[1] === 'string'
						// TODO: validate member[1] is a valid web socket?
					);
				});

			setConnectInfo({ value, isValid });
			// TODO: Show progress UI
		} catch {
			setConnectInfo({ value, isValid: false });
			// TODO: Show error UI
		}
	};

	const handleConnectFederation = async () => {
		if (!connectInfo.isValid) return;

		try {
			const federation = await mintgate.connectFederation(connectInfo.value);
			connect.renderConnectedFedCallback(federation);
			// TODO: Show success UI
		} catch (e: any) {
			// TODO: Show error UI
		}
	};

	return (
		<Collapse in={connect.isOpen} animateOpacity>
			<Box m='1'>
				<HStack
					borderRadius='4'
					p='8'
					boxShadow='rgba(0, 0, 0, 0.02) 0px 1px 3px 0px, rgba(27, 31, 35, 0.15) 0px 0px 0px 1px'
					mt='8'
					mb='4'
					spacing='4'
					alignItems='flex-end'
				>
					<Input
						labelName='Connect String:'
						placeHolder='Enter federation connection string'
						value={connectInfo.value}
						onChange={(event) => handleInputString(event)}
					/>
					<Button
						borderRadius='4'
						onClick={() => handleConnectFederation()}
						height='48px'
						disabled={!connectInfo.isValid}
					>
						Connect 🚀
					</Button>
				</HStack>
			</Box>
		</Collapse>
	);
};

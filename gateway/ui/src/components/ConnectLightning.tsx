import React, { useState } from 'react';
import { Box, Collapse, Stack } from '@chakra-ui/react';
import { isWebUri } from 'valid-url';
import { Button, Input } from '.';
import '../index.css';

export type ConnectLightningButtonProps = {
	isLnConnected: boolean;
	onClick: () => void;
};

export const ConnectLightningButton = (props: ConnectLightningButtonProps) => {
	return (
		<Button
			onClick={props.onClick}
			fontSize={{ base: '12px', md: '13px', lg: '16px' }}
			p={{ base: '10px', md: '13px', lg: '16px' }}
		>{`${props.isLnConnected ? 'Replace' : 'Connect'} Lightning`}</Button>
	);
};

export type ConnectLightningProps = {
	isOpen: boolean;
	isLnConnected: boolean;
	proposeGatewayLightningService: (url: URL) => Promise<void>;
};

interface LnrpcURL {
	value: string;
	isValid: boolean;
}

export const ConnectLightning = (props: ConnectLightningProps) => {
	const [url, updateUrl] = useState<LnrpcURL>({ value: '', isValid: false });

	const handleInputString = (event: React.ChangeEvent<HTMLInputElement>) => {
		event.preventDefault();

		const { value } = event.target;
		const validatedValue = isWebUri(value);
		if (validatedValue === undefined) {
			updateUrl({ value, isValid: false });
		} else {
			updateUrl({ value: validatedValue, isValid: true });
		}
	};

	const connectLightning = () => {
		props
			.proposeGatewayLightningService(new URL(url.value))
			.then(() => {
				// show success ui
			})
			.catch((e: any) => {
				// show error ui
				console.error(e);
			})
			.finally(() => {
				updateUrl({ value: '', isValid: false });
			});
	};

	return (
		<Collapse in={props.isOpen} animateOpacity>
			<Box m='1'>
				<Stack
					borderRadius='4'
					p={{ base: '16px', md: '24px', lg: '32px' }}
					boxShadow='rgba(0, 0, 0, 0.02) 0px 1px 3px 0px, rgba(27, 31, 35, 0.15) 0px 0px 0px 1px'
					mt='8'
					mb='4'
					gap={{ base: '8px', md: '24px', lg: '32px' }}
					alignItems='flex-end'
					className='connect-ln'
					flexDir='row'
				>
					<Input
						labelName={`${
							props.isLnConnected ? 'Replace' : 'Connect'
						} Lightning:`}
						placeHolder='Enter url to Gateway lightning service'
						value={url.value}
						onChange={(event) => handleInputString(event)}
					/>
					<Button
						borderRadius='4'
						onClick={connectLightning}
						height='48px'
						disabled={!url.isValid}
						fontSize={{ base: '12px', md: '13px', lg: '16px' }}
						p={{ base: '10px', md: '13px', lg: '16px' }}
					>
						Connect ⚡
					</Button>
				</Stack>
			</Box>
		</Collapse>
	);
};

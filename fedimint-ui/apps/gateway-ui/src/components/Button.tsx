import React from 'react';
import { Button as CustomButton, ResponsiveObject } from '@chakra-ui/react';

export type ButtonProps = {
	onClick: () => void;
	icon?: React.ReactSVGElement;
	size?: string;
	fontSize?: ResponsiveObject<string>;
	height?: string | number;
	width?: ResponsiveObject<string>;
	borderRadius?: string | number;
	isLoading?: boolean;
	disabled?: boolean;
	children?: React.ReactNode;
	p?: ResponsiveObject<string>;
};

export const Button = (props: ButtonProps) => {
	return (
		<CustomButton
			backgroundColor='black'
			color='white'
			_hover={{
				background: 'gray',
				color: 'white',
			}}
			{...props}
		>
			{props.children}
		</CustomButton>
	);
};

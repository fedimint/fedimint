import React from 'react';
import { InputGroup, Text, Input as CustomInput } from '@chakra-ui/react';

export type InputProps = {
	labelName: string;
	placeHolder: string;
	value: string | number;
	onChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
	name?: string;
};

export const Input = (input: InputProps) => {
	return (
		<InputGroup flexDir='column'>
			<Text
				fontSize='16px'
				color='#2d2d2d'
				opacity={'85%'}
				fontWeight='500'
				mb='4px'
			>
				{input.labelName}
			</Text>
			<CustomInput
				value={input.value}
				onChange={input.onChange}
				placeholder={input.placeHolder}
				height='48px'
				_placeholder={{ color: '#2d2d2d', opacity: '50%' }}
				name={input.name}
			/>
		</InputGroup>
	);
};

import React from 'react';
import { Flex, Image, Spacer } from '@chakra-ui/react';
import { ColorModeSwitcher } from './ColorModeSwitcher';
import Logo from './assets/Fedimint-Full.png';
// import { theme } from './theme';

export const Header = React.memo(() => {
	return (
		<Flex>
			<Flex
				alignItems='center'
				gap='2'
				maxW={{ base: '100%', sm: '50%', md: '50%', lg: '100%' }}
			>
				<Image src={Logo} alt='Fedimint Logo' boxSize='200px' height='45px' />
			</Flex>
			<Spacer />
			<ColorModeSwitcher justifySelf='flex-end' />
		</Flex>
	);
});

import React from 'react';
import {
	Button,
	Flex,
	Image,
	Radio,
	RadioGroup,
	VStack,
	HStack,
	Text,
} from '@chakra-ui/react';
import { GuardianRole } from '../types';

import Leader from './assets/Leader.png';
import Follower from './assets/Follower.png';
import { CustomButton } from './index';

interface RoleSelectorProps {
	selectGuardianRole: (role: GuardianRole) => void;
}

export const RoleSelector = React.memo(
	({ selectGuardianRole }: RoleSelectorProps) => {
		return (
			<>
				<VStack alignItems='left'>
					<Text fontSize='3xl'>Welcome to Fedimint!</Text>
					<Text fontSize='xl'>
						Are you setting up your Fedimint as a Leader or Follower?
					</Text>
				</VStack>

				<RoleOption
					image={Leader}
					text={'Leader'}
					description={
						'Choose one of your Guardians as a leader. The Leader will input \n information about the federation.'
					}
					selectOption={() => selectGuardianRole(GuardianRole.Host)}
				/>
				<RoleOption
					image={Follower}
					text={'Follower'}
					description={
						'Guardian Followers (all other Guardians) will confirm information that \n the Leader inputs.'
					}
					selectOption={() => selectGuardianRole(GuardianRole.Follower)}
				/>
				<CustomButton />
			</>
		);
	}
);

interface RoleOptionProps {
	image: string;
	text: string;
	description: string;
	selectOption: () => void;
}

export const RoleOption = React.memo(
	({ image, text, description, selectOption }: RoleOptionProps) => {
		return (
			<Button
				onClick={selectOption}
				_hover={{
					bg: '#EFF8FF',
					color: '#175CD3',
				}}
				mt={5}
				p={10}
				width='full'
				height={{
					base: '100%',
					md: '50%',
				}}
				size={{ base: 'sm', md: 'md', lg: 'lg' }}
				// fontSize={{ base: 'md', md: '16px', lg: 'xl' }}
				px={{ base: 4, md: 6, lg: 8 }}
			>
				<Flex gap={4} pr={5} alignItems='left' flexDirection='row'>
					<Image
						src={image}
						boxSize={{ base: '27px', md: '50px' }}
						objectFit='contain'
					/>
					<HStack alignItems='left' textAlign='start' flexDirection='column'>
						<Text
							fontSize={{ base: '12px', md: '16px', lg: '20px' }}
							mb={3}
							pl={2}
						>
							{text}
						</Text>
						<Text mb={8} fontSize={{ base: '10px', md: '12px', lg: '16px' }}>
							{description}
						</Text>
					</HStack>
				</Flex>
				<RadioGroup>
					<Radio colorScheme='#EFF8FF' pl={16} pb={10} />
				</RadioGroup>
			</Button>
		);
	}
);

import React from 'react';
import { Button, VStack, HStack, Text } from '@chakra-ui/react';
import { GuardianRole } from '../types';

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
					text={'Leader'}
					description={
						'Choose one of your Guardians as a leader. The Leader will input information about the federation.'
					}
					selectOption={() => selectGuardianRole(GuardianRole.Host)}
				/>
				<RoleOption
					text={'Follower'}
					description={
						'Guardian Followers (all other Guardians) will confirm information that the Leader inputs'
					}
					selectOption={() => selectGuardianRole(GuardianRole.Follower)}
				/>
			</>
		);
	}
);

interface RoleOptionProps {
	text: string;
	description: string;
	selectOption: () => void;
}

export const RoleOption = React.memo(
	({ text, description, selectOption }: RoleOptionProps) => {
		return (
			<Button onClick={selectOption}>
				<HStack alignItems='left'>
					<Text>{text}</Text>
					<Text>{description}</Text>
				</HStack>
			</Button>
		);
	}
);

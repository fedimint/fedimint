import React, { useState } from 'react';
import { ChakraProvider, Center, Box, Text, theme } from '@chakra-ui/react';
import { Header, RoleSelector } from './components';
import { GuardianRole } from './types';

export const App = React.memo(() => {
	const [role, setGuardianRole] = useState<GuardianRole | undefined>(undefined);

	const GetExperience = React.useCallback(() => {
		switch (role) {
		case GuardianRole.Host:
			return <Placeholder text='Leader' />;
		case GuardianRole.Follower:
			return <Placeholder text='Follower' />;
		default:
			return <RoleSelector selectGuardianRole={setGuardianRole} />;
		}
	}, [role]);

	return (
		<React.StrictMode>
			<ChakraProvider theme={theme}>
				<Center>
					<Box
						maxW='1000px'
						width='100%'
						minH='100%'
						mt={10}
						mb={10}
						mr={[2, 4, 6, 10]}
						ml={[2, 4, 6, 10]}
						p={5}
					>
						<Header />
						<Box mt={12}>{GetExperience()}</Box>
					</Box>
				</Center>
			</ChakraProvider>
		</React.StrictMode>
	);
});

const Placeholder = React.memo(({ text }: { text: string }) => {
	return <Text>{text}</Text>;
});

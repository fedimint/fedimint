import React, { useContext } from 'react';
import {
	ChakraProvider,
	Box,
	VStack,
	theme,
	Button,
	Heading,
} from '@chakra-ui/react';
import { ColorModeSwitcher } from './ColorModeSwitcher';
import {
	ACTION_TYPE,
	GuardianContext,
	GuardianProvider,
	UserType,
} from './context/context';

export const App: React.FC = () => {
	return (
		<ChakraProvider theme={theme}>
			<GuardianProvider>
				<Box textAlign='center' fontSize='xl'>
					<ColorModeSwitcher justifySelf='flex-end' />
					<VStack spacing={8}>
						<GuardianFlow />
					</VStack>
				</Box>
			</GuardianProvider>
		</ChakraProvider>
	);
};

const GuardianFlow: React.FC = () => {
	const { state, dispatch } = useContext(GuardianContext);

	const setStep = (step: number) => {
		dispatch({ type: ACTION_TYPE.SET_STEP, payload: step });
	};

	const setUserType = (userType: UserType) => {
		dispatch({ type: ACTION_TYPE.SET_USER_TYPE, payload: userType });
	};

	const nextStep = () => setStep(state.step + 1);
	const prevStep = () => setStep(state.step - 1);
	const NavButtons = (props: { no_next?: boolean; no_prev?: boolean }) => {
		const { no_next = false, no_prev = false } = props;
		return (
			<>
				{no_prev ? <></> : <Button onClick={prevStep}>Back</Button>}
				{no_next ? <></> : <Button onClick={nextStep}>Next</Button>}
			</>
		);
	};

	const handleUserTypeSelection = (type: UserType) => {
		setUserType(type);
		nextStep();
	};

	const renderStep = () => {
		switch (state.step) {
		case 1:
			return (
				<Box>
					<Heading>Welcome</Heading>
					<Button onClick={() => handleUserTypeSelection('Host')}>
							Host
					</Button>
					<Button onClick={() => handleUserTypeSelection('Non-Host')}>
							Non-Host
					</Button>
				</Box>
			);
		case 2:
			return (
				<Box>
					<h1>Settings</h1>
					{/* Add form fields depending on userType */}
					{state.userType === 'Host' ? (
						<p>Host settings</p>
					) : (
						<p>Non-Host settings</p>
					)}
					<NavButtons />
				</Box>
			);
		case 3:
			return (
				<Box>
					{state.userType === 'Host' ? (
						<Box>
							<h1>Invite Non-Hosts</h1>
							{/* Add form fields for inviting Non-Hosts */}
						</Box>
					) : (
						<Box>
							<h1>Join a Host</h1>
							{/* Add form fields to join a Host */}
						</Box>
					)}
					<NavButtons />
				</Box>
			);
		case 4:
			return (
				<Box>
					<h1>Confirmation</h1>
					{/* Display confirmation info */}
					<NavButtons />
				</Box>
			);
		case 5:
			return (
				<Box>
					<h1>Status</h1>
					{/* Display status of setup */}
					<NavButtons />
				</Box>
			);
		case 6:
			return (
				<Box>
					<h1>Share Verification Information</h1>
					{/* Add fields for sharing verification information */}
					<NavButtons />
				</Box>
			);
		case 7:
			return (
				<Box>
					<h1>Dashboard</h1>
					<NavButtons no_next />
					{/* Add dashboard contents */}
				</Box>
			);
		default:
			return <p>Invalid step</p>;
		}
	};

	return <>{renderStep()}</>;
};

export default App;

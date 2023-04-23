import { Button, Input, Text } from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { ApiContext } from './components/ApiProvider';


export const Admin = () => {
	const { api } = React.useContext(ApiContext);
	const [response, setResponse] = useState('');
	const [password, setPassword] = useState('');
	const [loggedIn, setLoggedIn] = useState(false);

	useEffect(() => {
		async function ping() {
			const result = await api.ping();
			setResponse(result);
		}
		ping();
	}, [response, setResponse]);

	async function onSubmit() {
		try {
			await api.setPassword(password);
			console.log('password set');
			setLoggedIn(true);
		} catch(e) {
			console.error('failed to set password', e);
		}
	}

	if (loggedIn) {
		return (
			<>
				<Text>Logged In</Text>
			</>
		);
	}

	return (
		<>
			<Input placeholder='password' onChange={e => setPassword(e.target.value)}/>
			<Button colorScheme='blue' onClick={onSubmit}>
				Login
			</Button>
		</>
	);
};
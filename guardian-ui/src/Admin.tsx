import { Button, Input } from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { ApiContext } from './components/ApiProvider';


const LoggedIn = () => {
	const { api } = React.useContext(ApiContext);
	async function onSetDefaults() {
		try {
			await api.setDefaults();
			console.log('defaults set');
		} catch(e) {
			console.error('failed to set defaults', e);
		}
	}
	async function onDkg() {
		try {
			await api.runDkg();
			console.log('ran dkg');
		} catch(e) {
			console.error('failed to run dkg', e);
		}
	}
	async function onVerify() {
		try {
			const status = await api.verify();
			console.log('verify', status);
		} catch(e) {
			console.error('failed to verify', e);
		}
	}
	async function onStatus() {
		try {
			const status = await api.status();
			console.log('status', status);
		} catch(e) {
			console.error('failed to get status', e);
		}
	}
	async function onStartConsensus() {
		try {
			const status = await api.startConsensus();
			console.log('startConsensus', status);
		} catch(e) {
			console.error('failed to startConsensus', e);
		}
	}
	return (
		<>
			<Button onClick={onSetDefaults}>
				Set Defaults
			</Button>
			<Button onClick={onDkg}>
				Run DKG
			</Button>
			<Button onClick={onVerify}>
				Verify
			</Button>
			<Button onClick={onStatus}>
				Status
			</Button>
			<Button onClick={onStartConsensus}>
				Start Consensus
			</Button>
		</>
	);
};

export const Admin = () => {
	const { api } = React.useContext(ApiContext);
	const [password, setPassword] = useState('');
	const [loggedIn, setLoggedIn] = useState(false);

	async function onSignup() {
		try {
			await api.setPassword(password);
			console.log('password set');
			setLoggedIn(true);
		} catch(e) {
			console.error('failed to set password', e);
		}
	}

	async function onLogin() {
		try {
			api.setPasswordLocal(password);
			console.log('password set');
			setLoggedIn(true);
		} catch(e) {
			console.error('failed to set password', e);
		}
	}

	// TODO: use server_status() to route here
	if (loggedIn) {
		return (
			<>
				<LoggedIn />
			</>
		);
	}

	return (
		<>
			<Input placeholder='password' onChange={e => setPassword(e.target.value)}/>
			<Button onClick={onLogin}>
				Login
			</Button>
			<Button onClick={onSignup}>
				Signup
			</Button>
		</>
	);
};
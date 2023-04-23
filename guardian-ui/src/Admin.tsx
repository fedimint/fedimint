import React, { useEffect, useState } from 'react';
import { ApiContext } from './components/ApiProvider';


export const Admin = () => {
	const { api } = React.useContext(ApiContext);
	const [response, setResponse] = useState('');

	useEffect(() => {
		async function ping() {
			const result = await api.ping();
			console.log('result', result);
			setResponse(result);
		}
		ping();
	}, [response, setResponse]);

	return (
		<div>
			<div>response: {response}</div>
		</div>
	);
};
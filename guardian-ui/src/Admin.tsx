// import React from 'react';
// import { Text, Center } from '@chakra-ui/react';


import { useState, useCallback } from 'react';
import useWebSocket, { ReadyState } from 'react-use-websocket';

export const Admin = () => {
	//Public API that will echo messages sent to it back to the client
	// const [socketUrl, setSocketUrl] = useState('wss://echo.websocket.org');
	const [socketUrl, setSocketUrl] = useState('ws://127.0.0.1:18174');
	// const [messageHistory, setMessageHistory] = useState([]);

	const { sendMessage, lastMessage, readyState } = useWebSocket(socketUrl);

	console.log(lastMessage);

	// useEffect(() => {
	// 	if (lastMessage !== null) {
	// 		setMessageHistory((prev) => prev.concat(lastMessage));
	// 	}
	// }, [lastMessage, setMessageHistory]);

	const handleClickChangeSocketUrl = useCallback(
		() => setSocketUrl('wss://demos.kaazing.com/echo'),
		[]
	);

	const handleClickSendMessage = useCallback(() => {
		const msg = {
			jsonrpc : '2.0',
			method : 'ping',
			id : '1',
			params: [
				{
					auth: null, 
					params:null 
				}
			]
		};
		const json = JSON.stringify(msg);
		sendMessage(json);
	}, []);

	const connectionStatus = {
		[ReadyState.CONNECTING]: 'Connecting',
		[ReadyState.OPEN]: 'Open',
		[ReadyState.CLOSING]: 'Closing',
		[ReadyState.CLOSED]: 'Closed',
		[ReadyState.UNINSTANTIATED]: 'Uninstantiated',
	}[readyState];

	return (
		<div>
			<button onClick={handleClickChangeSocketUrl}>
				Click Me to change Socket Url
			</button>
			<button
				onClick={handleClickSendMessage}
				disabled={readyState !== ReadyState.OPEN}
			>
				Click Me to send 'Hello'
			</button>
			<span>The WebSocket is currently {connectionStatus}</span>
			{lastMessage ? <span>Last message: {lastMessage.data}</span> : null}
			{/* <ul>
				{messageHistory.map((message, idx) => (
					<span key={idx}>{message ? message.data : null}</span>
				))}
			</ul> */}
		</div>
	);
};
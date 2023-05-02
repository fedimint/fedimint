import React from 'react';
import ReactDOM from 'react-dom/client';
import { ChakraProvider } from '@chakra-ui/react';
import { theme, Fonts } from './theme';
import { Admin } from './Admin';
import { BlockstreamExplorer, MockMintgate } from './api';
import './index.css';
import reportWebVitals from './reportWebVitals';
import { ApiProvider } from './components';

// Read environment variables
const gateway_api = process.env.REACT_APP_FEDIMINT_GATEWAY_API;

// TODO: Implement and use real Mintgate API calling into gateway_api server
const mintgate = gateway_api ? new MockMintgate() : new MockMintgate();

// TODO: Enable configuration to different block explorers
const explorer = new BlockstreamExplorer('https://blockstream.info/api/');

const root = ReactDOM.createRoot(
	document.getElementById('root') as HTMLElement
);

root.render(
	<React.StrictMode>
		<Fonts />
		<ChakraProvider theme={theme}>
			<ApiProvider props={{ mintgate, explorer }}>
				<Admin />
			</ApiProvider>
		</ChakraProvider>
	</React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();

import { ColorModeScript } from '@chakra-ui/react';
import * as React from 'react';
import * as ReactDOM from 'react-dom/client';
import { App } from './App';
import { i18nProvider } from '@fedimint/utils';
import { languages } from './languages';

i18nProvider(languages);

const container = document.getElementById('root');
if (!container) throw new Error('Failed to find the root element');
const root = ReactDOM.createRoot(container);

root.render(
  <React.StrictMode>
    <ColorModeScript />
    <App />
  </React.StrictMode>
);

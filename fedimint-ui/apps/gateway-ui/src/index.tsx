import React from 'react';
import ReactDOM from 'react-dom/client';
import { SharedChakraProvider, theme, Fonts } from '@fedimint/ui';
import { App } from './App';
import './index.css';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <Fonts />
    <SharedChakraProvider theme={theme}>
      <App />
    </SharedChakraProvider>
  </React.StrictMode>
);

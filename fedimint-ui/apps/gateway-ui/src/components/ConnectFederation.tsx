import React, { useState } from 'react';
import { Box, Button, Collapse, HStack } from '@chakra-ui/react';
import { ApiContext } from '../ApiProvider';
import { Input } from './Input';
import { Federation } from '../types';

export type ConnectFederationProps = {
  isOpen: boolean;
  renderConnectedFedCallback: (federation: Federation) => void;
};

export const ConnectFederation = (connect: ConnectFederationProps) => {
  const { gateway } = React.useContext(ApiContext);
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [connectInfo, setConnectInfo] = useState<string>('');

  const handleInputString = (event: React.ChangeEvent<HTMLInputElement>) => {
    event.preventDefault();
    setConnectInfo(event.target.value);
  };

  const handleConnectFederation = async () => {
    try {
      const federation = await gateway.connectFederation(connectInfo);
      connect.renderConnectedFedCallback(federation);
      setConnectInfo('');
    } catch (e) {
      setErrorMsg(`Failed to connect to federation ${e}`);
    }
  };

  return (
    <Collapse in={connect.isOpen} animateOpacity>
      <Box m='1'>
        <HStack
          borderRadius='4'
          p='8'
          boxShadow='rgba(0, 0, 0, 0.02) 0px 1px 3px 0px, rgba(27, 31, 35, 0.15) 0px 0px 0px 1px'
          mt='8'
          mb='4'
          spacing='4'
          alignItems='flex-end'
        >
          <Input
            labelName='Connection String:'
            placeHolder='Enter federation connection string'
            value={connectInfo}
            onChange={(event) => handleInputString(event)}
          />
          <Button
            borderRadius='4'
            onClick={() => handleConnectFederation()}
            height='48px'
          >
            Connect
          </Button>
          <Box color='red.500'>{errorMsg}</Box>
        </HStack>
      </Box>
    </Collapse>
  );
};

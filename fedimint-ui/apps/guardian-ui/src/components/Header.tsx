import React from 'react';
import { Flex, Image, Spacer } from '@chakra-ui/react';
import { ColorModeSwitcher } from './ColorModeSwitcher';
import Logo from '../assets/images/Fedimint-Full.png';

export const Header = React.memo(function Header() {
  return (
    <Flex width='100%'>
      <Flex alignItems='center' gap='2'>
        <Image
          src={Logo}
          alt='Fedimint Logo'
          boxSize='200px'
          height='45px'
          width='200px'
        />
      </Flex>
      <Spacer />
      <ColorModeSwitcher justifySelf='flex-end' />
    </Flex>
  );
});

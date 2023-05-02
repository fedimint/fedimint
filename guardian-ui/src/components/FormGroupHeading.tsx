import { Flex, Icon, Heading } from '@chakra-ui/react';
import React from 'react';

export const FormGroupHeading: React.FC<{
  icon: React.FunctionComponent<React.SVGAttributes<SVGElement>>;
  title: React.ReactNode;
}> = ({ icon, title }) => (
  <Flex align='center' justify='start' mb={-3}>
    <Icon width='20px' height='20px' mr={2} as={icon} />
    <Heading fontSize='md' lineHeight='20px' fontWeight='700'>
      {title}
    </Heading>
  </Flex>
);

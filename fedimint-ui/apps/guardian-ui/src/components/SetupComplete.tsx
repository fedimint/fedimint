import { Flex, Heading, Text, Button, Icon } from '@chakra-ui/react';
import React, { useCallback } from 'react';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { useGuardianContext } from '../hooks';
import { SETUP_ACTION_TYPE } from '../types';

export const SetupComplete: React.FC = () => {
  const { dispatch } = useGuardianContext();

  const handleContinue = useCallback(() => {
    dispatch({ type: SETUP_ACTION_TYPE.SET_IS_SETUP_COMPLETE, payload: true });
  }, [dispatch]);

  return (
    <Flex
      direction='column'
      justify='center'
      align='center'
      textAlign='center'
      pt={10}
    >
      <Heading size='sm' fontSize='42px' mb={8}>
        🎉 🎉 🎉
      </Heading>
      <Heading size='md' fontWeight='medium' mb={2}>
        Congratulations
      </Heading>
      <Text mb={16} fontWeight='medium'>
        All Guardians’ verification codes have been verified.
      </Text>
      <Button leftIcon={<Icon as={ArrowRightIcon} />} onClick={handleContinue}>
        Continue
      </Button>
    </Flex>
  );
};

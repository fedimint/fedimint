import { Flex, Heading, Text, Button, Icon } from '@chakra-ui/react';
import React, { useCallback } from 'react';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { useGuardianContext } from '../hooks';
import { SETUP_ACTION_TYPE } from '../types';
import { useTranslation } from '@fedimint/utils';

export const SetupComplete: React.FC = () => {
  const { dispatch } = useGuardianContext();
  const { t } = useTranslation();

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
        {t('setup_complete.header')}
      </Heading>
      <Heading size='md' fontWeight='medium' mb={2}>
        {t('setup_complete.congratulations')}
      </Heading>
      <Text mb={16} fontWeight='medium'>
        {t('setup_complete.sentence_one')}
      </Text>
      <Button leftIcon={<Icon as={ArrowRightIcon} />} onClick={handleContinue}>
        {t('setup_complete.continue')}
      </Button>
    </Flex>
  );
};

import React from 'react';
import { Box, Stack, TabPanel, Text } from '@chakra-ui/react';
import { TabHeader } from '.';
import { useTranslation } from '@fedimint/translation';

export const InfoTabHeader = (): JSX.Element => {
  const { t } = useTranslation('gateway');
  return <TabHeader>{t('info_tab.tab_header')}</TabHeader>;
};

interface InfoTabProps {
  date_created: string;
  description: string;
}

export const InfoTab = React.memo(function InfoTab(
  props: InfoTabProps
): JSX.Element {
  const { t } = useTranslation('gateway');
  const { description, date_created } = props;
  return (
    <TabPanel>
      <Stack spacing={2}>
        <Box>
          <Text fontWeight='500' fontSize='15px'>
            {t('info_tab.description')}
          </Text>
          <Text> {description}</Text>
        </Box>
        <Box>
          <Text fontWeight='500' fontSize='15px'>
            {t('info_tab.date_connected')}
          </Text>
          <Text>{date_created.toString().slice(0, 10)}</Text>
        </Box>
      </Stack>
    </TabPanel>
  );
});

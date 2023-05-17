import React from 'react';
import { Box, Stack, TabPanel, Text } from '@chakra-ui/react';
import { TabHeader } from '.';

export const InfoTabHeader = (): JSX.Element => {
  return <TabHeader>Info</TabHeader>;
};

interface InfoTabProps {
  date_created: string;
  description: string;
}

export const InfoTab = React.memo(function InfoTab(
  props: InfoTabProps
): JSX.Element {
  const { description, date_created } = props;
  return (
    <TabPanel>
      <Stack spacing={2}>
        <Box>
          <Text fontWeight='500' fontSize='15px'>
            Federation Description:
          </Text>
          <Text> {description}</Text>
        </Box>
        <Box>
          <Text fontWeight='500' fontSize='15px'>
            Date Connected:
          </Text>
          <Text>{date_created.toString().slice(0, 10)}</Text>
        </Box>
      </Stack>
    </TabPanel>
  );
});

import { Box } from '@chakra-ui/react';
import { ArrowForwardIcon } from '@chakra-ui/icons';

export const CustomButton = () => {
  return (
    <>
      <Box
        as='button'
        color='white'
        bgGradient='linear(to-r, #4AD6FF, #23419F)'
        width='88px'
        height='36px'
        borderRadius='8px'
        mt={20}
        pr={3}
        fontSize='16px'
        fontWeight={600}
      >
        <ArrowForwardIcon boxSize={6} pb={1} />
        Next
      </Box>
    </>
  );
};

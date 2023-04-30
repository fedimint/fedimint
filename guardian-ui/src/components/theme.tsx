import { extendTheme } from '@chakra-ui/react';

const theme = extendTheme({
	breakpoints: {
		sm: '30em',
		md: '48em',
		lg: '62em',
		xl: '80em',
		'2xl': '96em',
	},
});

export default theme;

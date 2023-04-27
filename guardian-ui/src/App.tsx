import {
	ChakraProvider,
	Box,
	Text,
	VStack,
	Grid,
	theme,
} from '@chakra-ui/react';
import { ColorModeSwitcher } from './ColorModeSwitcher';

export const App = () => (
	<ChakraProvider theme={theme}>
		<Box textAlign='center' fontSize='xl'>
			<Grid minH='100vh' p={3}>
				<ColorModeSwitcher justifySelf='flex-end' />
				<VStack spacing={8}>
					<Text>Guardian UI Coming soon!</Text>
				</VStack>
			</Grid>
		</Box>
	</ChakraProvider>
);

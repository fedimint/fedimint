import { Global } from '@emotion/react';
import { extendTheme } from '@chakra-ui/theme-utils';

const SPACE_GROTESK = 'Space Grotesk';
const INTER = 'Inter';

export const theme = extendTheme({
  fonts: {
    heading: `'${SPACE_GROTESK}', monospace`,
    body: `'${INTER}', sans-serif`,
  },
});

export const Fonts = () => (
  <Global
    styles={`
      @font-face {
        font-family: ${SPACE_GROTESK};
        font-style: normal;
        font-weight: 300 700;
        font-display: swap;
        src: url('/fonts/SpaceGrotesk-Variable.ttf') format('truetype');
      }

      @font-face {
        font-family: ${INTER};
        font-style: normal;
        font-weight: 100 900;
        font-display: swap;
        src: url('/fonts/Inter-Variable.ttf') format('truetype');
      }
    `}
  />
);

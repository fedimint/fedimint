import { Global } from '@emotion/react';
import { extendTheme, withDefaultColorScheme } from '@chakra-ui/react';

const SPACE_GROTESK = 'Space Grotesk';
const INTER = 'Inter';

const colors = {
  text: {
    primary: '#101828',
    secondary: '#475467',
  },
};

export const theme = extendTheme(
  {
    colors,
    fonts: {
      heading: `'${SPACE_GROTESK}', monospace`,
      body: `'${INTER}', sans-serif`,
    },
    components: {
      Text: {
        baseStyle: {
          color: colors.text.primary,
        },
        variants: {
          secondary: {
            color: colors.text.secondary,
          },
        },
      },
      Button: {
        baseStyles: {
          _disabled: {
            pointerEvents: 'none',
          },
        },
        sizes: {
          md: {
            height: '36px',
          },
        },
        variants: {
          solid: {
            bg: 'linear-gradient(72.82deg, #4AD6FF -62.43%, #23419F 63.9%)',
            color: '#FFF',
            _hover: {
              bg: 'linear-gradient(72.82deg, #4AD6FF -62.43%, #23419F 63.9%)',
              filter: 'brightness(1.1)',
            },
            _active: {
              bg: 'linear-gradient(72.82deg, #4AD6FF -62.43%, #23419F 63.9%)',
              filter: 'brightness(1.05)',
            },
            _disabled: {
              pointerEvents: 'none',
            },
          },
          ghost: {
            bg: 'transparent',
            border: '1px solid #EAECF0',
            _hover: {
              bg: '#EFF8FF',
            },
          },
        },
      },
    },
  },
  withDefaultColorScheme({ colorScheme: 'blue' })
);

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

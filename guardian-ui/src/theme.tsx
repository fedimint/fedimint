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

const blueGradient =
  'linear-gradient(72.82deg, #4AD6FF -62.43%, #23419F 63.9%)';
const inputShadow = '0px 1px 2px rgba(16, 24, 40, 0.05)';

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
        baseStyle: {
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
            bg: blueGradient,
            color: '#FFF',
            _hover: {
              bg: blueGradient,
              filter: 'brightness(1.1)',
            },
            _active: {
              bg: blueGradient,
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
      FormLabel: {
        baseStyle: {
          color: '#344054',
          fontSize: '14px',
          lineHeight: '20px',
        },
      },
      FormHelperText: {
        baseStyle: {
          color: colors.text.secondary,
        },
      },
      Input: {
        variants: {
          outline: {
            field: {
              border: '1px solid #D0D5DD',
              boxShadow: inputShadow,
            },
          },
        },
      },
      Select: {
        baseStyle: {
          field: {
            border: '1px solid #D0D5DD',
            boxShadow: inputShadow,
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

import { Global } from '@emotion/react';
import { extendTheme, withDefaultColorScheme } from '@chakra-ui/react';

const SPACE_GROTESK = 'Space Grotesk';
const INTER = 'Inter';

const colors = {
  text: {
    primary: '#101828',
    secondary: '#475467',
  },
  border: {
    input: '#D0D5DD',
    button: '#EAECF0',
    table: '#EAECF0',
    hover: '#A0AEC0',
    active: '#1849A9',
  },
};

const shadows = {
  xs: '0px 1px 2px rgba(16, 24, 40, 0.05)',
  sm: '0px 1px 3px rgba(16, 24, 40, 0.1), 0px 1px 2px rgba(16, 24, 40, 0.06)',
};

const blueGradient =
  'linear-gradient(72.82deg, #4AD6FF -62.43%, #23419F 63.9%)';

export const theme = extendTheme(
  {
    colors,
    shadows,
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
          outline: {
            bg: 'transparent',
            borderColor: colors.border.button,
            _hover: {
              bg: '#EFF8FF',
              borderColor: colors.border.hover,
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
              borderColor: colors.border.input,
              boxShadow: shadows.xs,
              _hover: {
                borderColor: colors.border.hover,
              },
            },
          },
        },
      },
      Select: {
        variants: {
          outline: {
            field: {
              borderColor: colors.border.input,
              boxShadow: shadows.xs,
              _hover: {
                borderColor: colors.border.hover,
              },
            },
          },
        },
      },
      Table: {
        basStyle: {
          colorScheme: 'gray',
        },
        defaultProps: {
          colorScheme: 'gray',
        },
        variants: {
          simple: {
            colorScheme: 'gray',
            padding: 4,
            borderWidth: 1,
            borderColor: colors.border.input,
            borderRadius: 12,
            borderCollapse: 'separate',
          },
        },
      },
    },
  },
  // By default all components use blue color scheme
  withDefaultColorScheme({ colorScheme: 'blue' }),
  // Override some components to use gray color scheme
  withDefaultColorScheme({ colorScheme: 'gray', components: ['Table'] })
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

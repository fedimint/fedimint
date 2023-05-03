import { Global } from '@emotion/react';
import { extendTheme, withDefaultColorScheme } from '@chakra-ui/react';

const SPACE_GROTESK = 'Space Grotesk';
const INTER = 'Inter';

const palette = {
  black: '#000000',
  white: '#FFFFFF',
  gray: {
    25: '#FCFCFD',
    50: '#F9FAFB',
    100: '#F2F4F7',
    200: '#EAECF0',
    300: '#D0D5DD',
    400: '#98A2B3',
    500: '#667085',
    600: '#475467',
    700: '#344054',
    800: '#1D2939',
    900: '#101828',
  },
  blue: {
    25: '#F5FAFF',
    50: '#EFF8FF',
    100: '#D1E9FF',
    200: '#B2DDFF',
    300: '#84CAFF',
    400: '#53B1FD',
    500: '#2E90FA',
    600: '#1570EF',
    700: '#175CD3',
    800: '#1849A9',
    900: '#194185',
  },
};

const shadows = {
  // System
  xs: `0px 1px 2px ${hexToRgba(palette.gray[900], 0.05)}`,
  sm: `0px 1px 3px ${hexToRgba(
    palette.gray[900],
    0.1
  )}, 0px 1px 2px  ${hexToRgba(palette.gray[900], 0.06)}`,
  // Overrides
  outline: `0 0 0 2px ${palette.blue[200]}`,
};

const colors = {
  ...palette,
  text: {
    primary: palette.gray[900],
    secondary: palette.gray[600],
    label: palette.gray[700],
  },
  border: {
    input: palette.gray[300],
    button: palette.gray[200],
    table: palette.gray[200],
    hover: palette.gray[400],
    active: palette.blue[800],
  },
};

export const theme = extendTheme(
  {
    colors,
    shadows,
    fonts: {
      heading: `'${SPACE_GROTESK}', monospace`,
      body: `'${INTER}', sans-serif`,
    },
    textStyles: {
      xs: {
        fontSize: '12px',
        lineHeight: '18px',
      },
      sm: {
        fontSize: '14px',
        lineHeight: '20px',
      },
      md: {
        fontSize: '16px',
        lineHeight: '24px',
      },
      lg: {
        fontSize: '18px',
        lineHeight: '28px',
      },
      xl: {
        fontSize: '20px',
        lineHeight: '30px',
      },
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
      Heading: {
        sizes: {
          xs: {
            fontSize: '24px',
            lineHeight: '32px',
          },
          sm: {
            fontSize: '30px',
            lineHeight: '38px',
          },
          md: {
            fontSize: '36px',
            lineHeight: '44px',
          },
          lg: {
            fontSize: '48px',
            lineHeight: '60px',
          },
          xl: {
            fontSize: '60px',
            lineHeight: '72px',
          },
          '2xl': {
            fontSize: '72px',
            lineHeight: '90px',
          },
        },
        variants: {
          xs: {
            fontSize: 100,
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
            bg: colors.blue[600],
            color: colors.white,
            _hover: {
              bg: colors.blue[700],
            },
            _active: {
              bg: colors.blue[600],
              boxShadow: `0 0 0 2px ${colors.blue[200]}`,
            },
            _disabled: {
              pointerEvents: 'none',
            },
          },
          outline: {
            bg: 'transparent',
            borderColor: colors.border.button,
            _hover: {
              bg: colors.blue[50],
              borderColor: colors.border.hover,
            },
          },
        },
      },
      FormLabel: {
        baseStyle: {
          color: colors.text.label,
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

/**
 * Given a hex value and an opacity from 0-1, convert to rgba notation.
 */
export function hexToRgba(hexCode: string, opacity: number) {
  let hex = hexCode.replace('#', '');

  // Handle #RGB hex
  if (hex.length === 3) {
    hex = `${hex[0]}${hex[0]}${hex[1]}${hex[1]}${hex[2]}${hex[2]}`;
  }

  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);

  return `rgba(${r},${g},${b},${opacity})`;
}

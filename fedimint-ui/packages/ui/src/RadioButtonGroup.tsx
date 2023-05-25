import React from 'react';
import {
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  useTheme,
} from '@chakra-ui/react';

export interface RadioButtonOption<T extends string | number> {
  icon: React.FunctionComponent<React.SVGAttributes<SVGElement>>;
  label: React.ReactNode;
  description: React.ReactNode;
  value: T;
}

export interface RadioButtonGroupProps<T extends string | number> {
  options: RadioButtonOption<T>[];
  value?: T;
  activeIcon?: React.FunctionComponent<React.SVGAttributes<SVGElement>>;
  onChange(value: T): void;
}

export function RadioButtonGroup<T extends string | number>({
  options,
  value,
  onChange,
  activeIcon,
}: RadioButtonGroupProps<T>): React.ReactElement {
  const theme = useTheme();
  const defaultStyles = {
    background: theme.colors.white,
    borderColor: theme.colors.gray[200],
    _hover: {
      borderColor: theme.colors.blue[300],
    },
    _focus: {
      boxShadow: theme.shadows.outline,
    },
    _active: {
      borderColor: theme.colors.blue[400],
      boxShadow: 'none',
    },
  };
  const activeStyles = {
    bg: theme.colors.blue[50],
    borderColor: theme.colors.blue[600],
    boxShadow: `0 0 0 1px ${theme.colors.blue[600]}`,
  };

  return (
    <VStack gap={1} align='left'>
      {options.map((option) => {
        const isActive = option.value === value;
        return (
          <Button
            key={option.value}
            onClick={() => onChange(option.value)}
            variant='outline'
            pl={4}
            pr={4}
            width='full'
            maxWidth={660}
            height={106}
            borderRadius={12}
            textAlign='left'
            margin={0}
            isActive={isActive}
            sx={isActive ? activeStyles : defaultStyles}
            role='group'
          >
            <HStack maxWidth='100%' gap={3} align='start'>
              <Flex
                width='40px'
                height='40px'
                align='center'
                justify='center'
                bg={theme.colors.blue[100]}
                boxShadow={`0 0 0 6px ${theme.colors.blue[50]}`}
                borderRadius='100%'
                mixBlendMode='multiply'
              >
                <Icon as={option.icon} />
              </Flex>
              <VStack align='start' flex={1} minWidth={0} wrap='wrap'>
                <Text
                  fontWeight='medium'
                  color={isActive ? theme.colors.blue[800] : undefined}
                >
                  {option.label}
                </Text>
                <Text
                  variant='secondary'
                  fontWeight='normal'
                  whiteSpace='break-spaces'
                  color={isActive ? theme.colors.blue[700] : undefined}
                >
                  {option.description}
                </Text>
              </VStack>
              <Flex
                align='center'
                justify='center'
                boxSize='20px'
                borderRadius='100%'
                transitionProperty={theme.transition.property.common}
                transitionDuration={theme.transition.duration.normal}
                sx={
                  isActive
                    ? {
                        bg: theme.colors.blue[700],
                        border: `1px solid ${theme.colors.blue[700]}`,
                        color: theme.colors.white,
                      }
                    : {
                        bg: theme.colors.white,
                        border: `1px solid ${theme.colors.gray[300]}`,
                        _groupHover: {
                          bg: theme.colors.blue[100],
                          borderColor: theme.colors.blue[600],
                        },
                        _groupFocus: {
                          bg: theme.colors.white,
                          borderColor: theme.colors.blue[300],
                          boxShadow: theme.shadows.outline,
                        },
                        _groupActive: {
                          bg: theme.colors.blue[200],
                          borderColor: theme.colors.blue[600],
                          boxShadow: 'none',
                        },
                      }
                }
              >
                {isActive && activeIcon && <Icon as={activeIcon} />}
              </Flex>
            </HStack>
          </Button>
        );
      })}
    </VStack>
  );
}

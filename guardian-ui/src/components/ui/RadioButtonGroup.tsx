import {
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Radio,
  Flex,
  useTheme,
} from '@chakra-ui/react';
import React from 'react';

export interface RadioButtonOption<T extends string | number> {
  icon: React.FunctionComponent<React.SVGAttributes<SVGElement>>;
  label: React.ReactNode;
  description: React.ReactNode;
  value: T;
}

export interface RadioButtonGroupProps<T extends string | number> {
  options: RadioButtonOption<T>[];
  value?: T;
  onChange(value: T): void;
}

export function RadioButtonGroup<T extends string | number>({
  options,
  value,
  onChange,
}: RadioButtonGroupProps<T>): React.ReactElement {
  const theme = useTheme();
  const activeStyles = {
    borderColor: theme.colors.blue[600],
    boxShadow: `0 0 0 1px ${theme.colors.blue[600]} inset`,
    bg: theme.colors.blue[50],
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
            _hover={{
              bg: '#EFF8FF',
              color: '#175CD3',
            }}
            pl={4}
            pr={4}
            width='full'
            maxWidth={660}
            height={106}
            borderRadius={12}
            textAlign='left'
            margin={0}
            {...(isActive ? activeStyles : {})}
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
              >
                <Icon as={option.icon} />
              </Flex>
              <VStack align='start' flex={1} minWidth={0} wrap='wrap'>
                <Text
                  fontWeight='500'
                  color={isActive ? theme.colors.blue[800] : undefined}
                >
                  {option.label}
                </Text>
                <Text
                  variant='secondary'
                  fontWeight='400'
                  whiteSpace='break-spaces'
                  color={isActive ? theme.colors.blue[600] : undefined}
                >
                  {option.description}
                </Text>
              </VStack>
              <Radio isChecked={value === option.value} />
            </HStack>
          </Button>
        );
      })}
    </VStack>
  );
}

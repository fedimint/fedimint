import React from 'react';
import {
  InputGroup,
  Input,
  Button,
  InputRightElement,
  useTheme,
  useClipboard,
} from '@chakra-ui/react';

export interface CopyInputProps {
  value: string;
  size?: 'md' | 'lg';
  buttonLeftIcon?: React.ReactElement;
}

export const CopyInput: React.FC<CopyInputProps> = ({
  value,
  size = 'md',
  buttonLeftIcon,
}) => {
  const { onCopy, hasCopied } = useClipboard(value);
  const theme = useTheme();

  return (
    <InputGroup width='100%' size={size}>
      <Input readOnly value={value} width='100%' />
      <InputRightElement
        borderLeft={`1px solid ${theme.colors.border.input}`}
        width={size === 'lg' ? 115 : 100}
        pr={'1px'}
      >
        <Button
          variant='ghost'
          leftIcon={buttonLeftIcon}
          onClick={onCopy}
          borderTopLeftRadius={0}
          borderBottomLeftRadius={0}
          size={size}
          height={size == 'lg' ? '46px' : '42px'}
          width='100%'
          colorScheme='gray'
          bg={theme.colors.white}
        >
          {hasCopied ? 'Copied' : 'Copy'}
        </Button>
      </InputRightElement>
    </InputGroup>
  );
};

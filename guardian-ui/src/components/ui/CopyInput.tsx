import {
  InputGroup,
  Input,
  Button,
  Icon,
  InputRightElement,
  useTheme,
  useClipboard,
} from '@chakra-ui/react';
import React from 'react';
import { ReactComponent as CopyIcon } from '../../assets/svgs/copy.svg';

export interface CopyInputProps {
  value: string;
  size?: 'md' | 'lg';
}

export const CopyInput: React.FC<CopyInputProps> = ({ value, size = 'md' }) => {
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
          leftIcon={<Icon as={CopyIcon} />}
          onClick={onCopy}
          borderTopLeftRadius={0}
          borderBottomLeftRadius={0}
          size={size}
          height={size == 'lg' ? '46px' : '38px'}
          width='100%'
        >
          {hasCopied ? 'Copied' : 'Copy'}
        </Button>
      </InputRightElement>
    </InputGroup>
  );
};

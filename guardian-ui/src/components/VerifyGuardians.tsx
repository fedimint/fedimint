import {
  Button,
  Flex,
  FormControl,
  FormLabel,
  Icon,
  Input,
  VStack,
  useClipboard,
} from '@chakra-ui/react';
import React, { useState } from 'react';
import { FormGroup } from './FormGroup';
import { FormGroupHeading } from './FormGroupHeading';
import { useGuardianContext } from '../hooks';
import { GuardianRole } from '../types';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';

interface Props {
  next(): void;
}

export const VerifyGuardians: React.FC<Props> = ({ next }) => {
  const {
    state: { role },
  } = useGuardianContext();
  const isHost = role === GuardianRole.Host;
  const [verificationCode] = useState('verifyCodePlaceholder');
  const {
    onCopy,
    value: clipValue,
    setValue,
    hasCopied,
  } = useClipboard(verificationCode);

  const [numberOfOtherGuardians] = useState(3);
  const [otherGuardiansVerificationCodes, setOtherGuardiansVerificationCodes] =
    useState(
      Array.from({ length: numberOfOtherGuardians }, () => {
        return '';
      })
    );

  const isValid = otherGuardiansVerificationCodes.every((x) => x !== '');

  const otherVerificationCodes = otherGuardiansVerificationCodes.map(
    (value, index) => {
      const handleChange = (ev: React.ChangeEvent<HTMLInputElement>) => {
        const newValues = [...otherGuardiansVerificationCodes];
        newValues[index] = ev.target.value;
        setOtherGuardiansVerificationCodes(newValues);
      };
      const readableIndex = isHost ? index + 1 : index;
      const label =
        !isHost && index === 0 ? 'Leader' : `Guardian ${readableIndex}`;

      return (
        <FormControl isRequired mb={3}>
          <FormLabel>{label}</FormLabel>
          <Input value={value} onChange={handleChange} />
        </FormControl>
      );
    }
  );

  return (
    <VStack gap={8} justify='start' align='start'>
      <FormGroup>
        <FormControl>
          <FormLabel>Share your verification code.</FormLabel>
          <Flex>
            <Input
              value={clipValue}
              readOnly={true}
              onChange={(e) => {
                setValue(e.target.value);
              }}
              mr={2}
            />
            <Button onClick={onCopy}>{hasCopied ? 'Copied!' : 'Copy'}</Button>
          </Flex>
        </FormControl>
      </FormGroup>
      <FormGroup>
        <FormControl>
          <FormGroupHeading title="Enter each guardian's verification code" />
          {otherVerificationCodes}
        </FormControl>
      </FormGroup>
      <div>
        {!isValid && <FormLabel>All codes must be entered</FormLabel>}
        <Button
          isDisabled={!isValid}
          onClick={isValid ? next : undefined}
          leftIcon={<Icon as={ArrowRightIcon} />}
          mt={4}
        >
          Next
        </Button>
      </div>
    </VStack>
  );
};

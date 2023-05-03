import {
  Button,
  CircularProgress,
  FormControl,
  FormLabel,
  Heading,
  Icon,
  Input,
  VStack,
} from '@chakra-ui/react';
import React, { useEffect, useState } from 'react';
import { FormGroup } from './FormGroup';
import { FormGroupHeading } from './FormGroupHeading';
import { useGuardianContext } from '../hooks';
import { GuardianRole } from '../types';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { CopyInput } from './ui/CopyInput';

interface Props {
  next(): void;
}

export const VerifyGuardians: React.FC<Props> = ({ next }) => {
  const {
    state: { role },
  } = useGuardianContext();
  const isHost = role === GuardianRole.Host;
  const [isAwaitingDKG, setIsAwaitingDKG] = useState(true);

  // Temp timer to simulate loading
  useEffect(() => {
    if (isAwaitingDKG) {
      const timer = setTimeout(() => {
        setIsAwaitingDKG(false);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [isAwaitingDKG]);

  const [verificationCode] = useState('verifyCodePlaceholder');

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

  if (isAwaitingDKG) {
    return (
      <VStack gap={8} justify='center' align='center'>
        <CircularProgress isIndeterminate color='#23419F' size='200px' />
        <Heading>Generating codes...</Heading>
      </VStack>
    );
  }
  return (
    <VStack gap={8} justify='start' align='start'>
      <FormGroup>
        <FormControl>
          <FormLabel>Share your verification code.</FormLabel>
          <CopyInput value={verificationCode} />
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

import React, { useMemo, useState } from 'react';
import { Button, VStack, Text, Heading, Icon } from '@chakra-ui/react';
import { GuardianRole } from '../types';

import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { ReactComponent as StarsIcon } from '../assets/svgs/stars.svg';
import { ReactComponent as IntersectSquareIcon } from '../assets/svgs/intersect-square.svg';
import { RadioButtonGroup, RadioButtonOption } from './ui/RadioButtonGroup';

interface RoleSelectorProps {
  selectGuardianRole: (role: GuardianRole) => void;
}

export const RoleSelector = React.memo(
  ({ selectGuardianRole }: RoleSelectorProps) => {
    const [role, setRole] = useState<GuardianRole>();
    const options: RadioButtonOption<GuardianRole>[] = useMemo(
      () => [
        {
          value: GuardianRole.Host,
          label: 'Leader',
          description:
            'Choose one of your Guardians as a Leader. The Leader will input information about the Federation.',
          icon: StarsIcon,
        },
        {
          value: GuardianRole.Follower,
          label: 'Follower',
          description:
            'Guardian Followers (all other Guardians) will confirm information that the Leader inputs.',
          icon: IntersectSquareIcon,
        },
      ],
      []
    );
    return (
      <VStack gap={8} align='left' justify='left'>
        <VStack align='left' gap={2}>
          <Heading fontSize={32} fontWeight='500'>
            Welcome to Fedimint!
          </Heading>
          <Text fontSize={16} fontWeight='500'>
            Are you creating a Federation, or joining one?
          </Text>
        </VStack>

        <RadioButtonGroup
          options={options}
          value={role}
          onChange={(value) => setRole(value)}
        />

        <div>
          <Button
            width='auto'
            leftIcon={<Icon as={ArrowRightIcon} />}
            disabled={!role}
            onClick={() => role && selectGuardianRole(role)}
          >
            Next
          </Button>
        </div>
      </VStack>
    );
  }
);

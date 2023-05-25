import React, { useCallback, useMemo, useState } from 'react';
import { Button, VStack, Icon } from '@chakra-ui/react';
import { RadioButtonGroup, RadioButtonOption } from '@fedimint/ui';
import { GuardianRole, SETUP_ACTION_TYPE } from '../types';
import { ReactComponent as ArrowRightIcon } from '../assets/svgs/arrow-right.svg';
import { ReactComponent as CheckIcon } from '../assets/svgs/check.svg';
import { ReactComponent as StarsIcon } from '../assets/svgs/stars.svg';
import { ReactComponent as IntersectSquareIcon } from '../assets/svgs/intersect-square.svg';
import { useGuardianContext } from '../hooks';

interface Props {
  next: () => void;
}

export const RoleSelector = React.memo<Props>(function RoleSelector({
  next,
}: Props) {
  const { dispatch } = useGuardianContext();
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

  const handleNext = useCallback(() => {
    if (!role) return;
    dispatch({ type: SETUP_ACTION_TYPE.SET_ROLE, payload: role });
    next();
  }, [role, dispatch, next]);

  return (
    <VStack gap={8} align='left' justify='left'>
      <RadioButtonGroup
        options={options}
        value={role}
        onChange={(value) => setRole(value)}
        activeIcon={CheckIcon}
      />

      <div>
        <Button
          width='auto'
          leftIcon={<Icon as={ArrowRightIcon} />}
          isDisabled={!role}
          onClick={handleNext}
        >
          Next
        </Button>
      </div>
    </VStack>
  );
});

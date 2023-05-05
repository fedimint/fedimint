import React, { useCallback } from 'react';
import {
  Box,
  Button,
  Text,
  Heading,
  Icon,
  VStack,
  Spinner,
} from '@chakra-ui/react';
import { ReactComponent as ArrowLeftIcon } from '../assets/svgs/arrow-left.svg';
import { Header } from './Header';
import { useGuardianContext } from '../hooks';
import { GuardianRole, SetupProgress, SETUP_ACTION_TYPE } from '../types';
import { RoleSelector } from './RoleSelector';
import { SetConfiguration } from './SetConfiguration';
import { Login } from './Login';
import { ConnectGuardians } from './ConnectGuardians';
import { RunDKG } from './RunDKG';
import { VerifyGuardians } from './VerifyGuardians';

const PROGRESS_ORDER: SetupProgress[] = [
  SetupProgress.Start,
  SetupProgress.SetConfiguration,
  SetupProgress.ConnectGuardians,
  SetupProgress.RunDKG,
  SetupProgress.VerifyGuardians,
  SetupProgress.SetupComplete,
];

export const Setup: React.FC = () => {
  const {
    state: { progress, role, password, needsAuth, isInitializing },
    dispatch,
  } = useGuardianContext();

  const isHost = role === GuardianRole.Host;
  const progressIdx = PROGRESS_ORDER.indexOf(progress);
  const prevProgress: SetupProgress | undefined =
    PROGRESS_ORDER[progressIdx - 1];
  const nextProgress: SetupProgress | undefined =
    PROGRESS_ORDER[progressIdx + 1];

  const handleBack = useCallback(() => {
    if (!prevProgress) return;
    dispatch({ type: SETUP_ACTION_TYPE.SET_PROGRESS, payload: prevProgress });
  }, [dispatch, prevProgress]);

  const handleNext = useCallback(() => {
    if (!nextProgress) return;
    dispatch({ type: SETUP_ACTION_TYPE.SET_PROGRESS, payload: nextProgress });
  }, [dispatch, nextProgress]);

  let title: React.ReactNode;
  let subtitle: React.ReactNode;
  let canGoBack = true;
  let content: React.ReactNode = (
    <>
      {/* TODO: Remove these defaults */}
      <Heading>Nothing here yet!</Heading>
      <Button onClick={handleNext}>Next</Button>
    </>
  );
  if (isInitializing) {
    content = <Spinner />;
  } else if (needsAuth && !password) {
    title = 'Welcome back!';
    subtitle = 'Please enter your password.';
    content = <Login />;
  } else {
    switch (progress) {
      case SetupProgress.Start:
        title = 'Welcome to Fedimint!';
        subtitle = 'Are you creating a Federation, or joining one?';
        content = <RoleSelector next={handleNext} />;
        break;
      case SetupProgress.SetConfiguration:
        title = 'Let’s set up your federation';
        subtitle = isHost
          ? 'Your Federation Followers will confirm this information on their end.'
          : 'Your Federation Leader will be setting up main Federation details. You’ll confirm them soon.';
        content = <SetConfiguration next={handleNext} />;
        break;
      case SetupProgress.ConnectGuardians:
        title = isHost
          ? 'Invite your Guardians'
          : 'Confirm your Federation Information';
        subtitle = isHost
          ? 'Share the link with the other Guardians to get everyone on the same page. Once all the Guardians join, you’ll automatically move on to the next step.'
          : 'Make sure that the information here looks right, and that the Federation Guardians are correct. Click the Approve button when you’re sure it looks good.';
        content = <ConnectGuardians next={handleNext} />;
        break;
      case SetupProgress.RunDKG:
        title = 'Boom! Sharing info between Guardians';
        subtitle =
          'All Guardians have validated federation setup details. Running some numbers...';
        content = <RunDKG next={handleNext} />;
        break;
      case SetupProgress.VerifyGuardians:
        title = 'Verify your Guardians';
        subtitle =
          'Ask each Guardian for their verification code, and paste them below to check validity. We’re almost done!';
        content = <VerifyGuardians next={handleNext} />;
        canGoBack = false;
        break;
      case SetupProgress.SetupComplete:
        title = 'Your Federation is now set up!';
        subtitle = 'Get connected and start inviting members.';
        canGoBack = false;
        break;
      default:
        title = 'Unknown step';
        subtitle = 'How did you get here?!';
    }
  }

  return (
    <VStack gap={8} align='start'>
      <Header />
      <VStack align='start' gap={2}>
        {prevProgress && canGoBack && (
          <Button
            variant='link'
            onClick={handleBack}
            leftIcon={<Icon as={ArrowLeftIcon} />}
          >
            Back
          </Button>
        )}
        {title && (
          <Heading size='md' fontWeight='medium'>
            {title}
          </Heading>
        )}
        {subtitle && (
          <Text size='md' fontWeight='medium'>
            {subtitle}
          </Text>
        )}
      </VStack>
      <Box mt={10} width='100%'>
        {content}
      </Box>
    </VStack>
  );
};

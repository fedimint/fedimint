import React, { useCallback, useEffect, useState } from 'react';
import {
  Center,
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
import {
  GuardianRole,
  SetupProgress,
  SETUP_ACTION_TYPE,
  ServerStatus,
} from '../types';
import { RoleSelector } from './RoleSelector';
import { SetConfiguration } from './SetConfiguration';
import { Login } from './Login';

const PROGRESS_ORDER: SetupProgress[] = [
  SetupProgress.Start,
  SetupProgress.SetConfiguration,
  SetupProgress.ConnectGuardians,
  SetupProgress.VerifyGuardians,
  SetupProgress.SetupComplete,
];

export const Setup: React.FC = () => {
  const {
    api,
    state: { progress, role, password },
    dispatch,
  } = useGuardianContext();
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);
  const [needsAuth, setNeedsAuth] = useState(false);

  const isHost = role === GuardianRole.Host;
  const progressIdx = PROGRESS_ORDER.indexOf(progress);
  const prevProgress: SetupProgress | undefined =
    PROGRESS_ORDER[progressIdx - 1];
  const nextProgress: SetupProgress | undefined =
    PROGRESS_ORDER[progressIdx + 1];

  useEffect(() => {
    setIsCheckingStatus(true);

    try {
      api.status().then((status) => {
        if (status === ServerStatus.AwaitingPassword) {
          dispatch({
            type: SETUP_ACTION_TYPE.SET_INITIAL_STATE,
            payload: null,
          });
        } else {
          setNeedsAuth(true);
        }
      });
    } catch (err) {
      // TODO: Show error UI
      console.error(err);
    }

    setIsCheckingStatus(false);
  }, [api]);

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
  let content: React.ReactNode = (
    <>
      {/* TODO: Remove these defaults */}
      <Heading>Nothing here yet!</Heading>
      <Button onClick={handleNext}>Next</Button>
    </>
  );
  if (isCheckingStatus) {
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
          : 'Join your Federation Leader';
        subtitle = isHost
          ? 'Share the link with the other Guardians to get everyone on the same page. Once all the Guardians join, you’ll automatically move on to the next step.'
          : 'Get your invite link from your Federation Leader, and paste it below.';
        break;
      case SetupProgress.VerifyGuardians:
        title = 'Verify your Guardians';
        subtitle =
          'Ask each Guardian for their verification code, and paste them below to check validity. We’re almost done!';
        break;
      case SetupProgress.SetupComplete:
        title = 'Your Federation is now set up!';
        subtitle = 'Get connected and start inviting members.';
        break;
      default:
        title = 'Unknown step';
        subtitle = 'How did you get here?!';
    }
  }

  return (
    <>
      <Center>
        <Box
          maxW='960px'
          width='100%'
          mt={10}
          mb={10}
          mr={[2, 4, 6, 10]}
          ml={[2, 4, 6, 10]}
          p={5}
        >
          <VStack gap={8} align='start'>
            <Header />
            <VStack align='start' gap={2}>
              {prevProgress && (
                <Button
                  variant='link'
                  onClick={handleBack}
                  leftIcon={<Icon as={ArrowLeftIcon} />}
                >
                  Back
                </Button>
              )}
              {title && (
                <Heading fontSize={32} lineHeight='3xl' fontWeight='500'>
                  {title}
                </Heading>
              )}
              {subtitle && (
                <Text size='md' lineHeight='shorter' fontWeight='500'>
                  {subtitle}
                </Text>
              )}
            </VStack>
            <Box mt={10}>{content}</Box>
          </VStack>
        </Box>
      </Center>
    </>
  );
};

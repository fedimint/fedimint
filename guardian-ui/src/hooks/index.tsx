import { useContext, useEffect } from 'react';
import { GuardianContext } from '../GuardianContext';

export function useGuardianContext() {
  return useContext(GuardianContext);
}

/**
 * Tells the guardian context to poll for updates. Handles turning off polling
 * on dismount.
 */
export function useConsensusPolling(shouldPoll = true) {
  const { toggleConsensusPolling } = useGuardianContext();

  useEffect(() => {
    if (!shouldPoll) return;
    toggleConsensusPolling(true);
    return () => toggleConsensusPolling(false);
  }, [shouldPoll]);
}

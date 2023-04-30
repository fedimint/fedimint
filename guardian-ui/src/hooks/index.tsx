import { useContext } from 'react';
import { GuardianContext } from '../GuardianContext';

export function useGuardianContext() {
  return useContext(GuardianContext);
}

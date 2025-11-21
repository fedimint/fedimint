import { storeJson } from './fileModels/store.json'
import { sdk } from './sdk'

export const setDependencies = sdk.setupDependencies(async ({ effects }) => {
  const backendType = await storeJson.read((s) => s.backendType).const(effects)

  if (backendType === 'bitcoind') {
    return {
      bitcoind: {
        kind: 'running',
        healthChecks: ['primary', 'sync-progress'],
        versionRange: '>=29.1',
      },
    }
  }

  return {}
})

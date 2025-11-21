import { setBackend } from '../actions/setBackend'
import { storeJson } from '../fileModels/store.json'
import { sdk } from '../sdk'

export const setBackendTask = sdk.setupOnInit(async (effects, _) => {
  const backendType = await storeJson.read((s) => s.backendType).const(effects)

  if (!backendType) {
    await sdk.action.createOwnTask(effects, setBackend, 'critical', {
      reason: 'Fedimint needs to know how to connect to the Bitcoin network',
    })
  }
})

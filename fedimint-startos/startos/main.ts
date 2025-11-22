import { storeJson } from './fileModels/store.json'
import { sdk } from './sdk'
import { uiPort } from './utils'

export const main = sdk.setupMain(async ({ effects, started }) => {
  /**
   * ======================== Setup (optional) ========================
   *
   * In this section, we fetch any resources or run any desired preliminary commands.
   */
  console.info('Starting Fedimint!')

  const store = await storeJson.read().const(effects)

  if (!store) {
    throw new Error('no store')
  }

  const depResult = await sdk.checkDependencies(effects)
  depResult.throwIfNotSatisfied()

  const env: Record<string, string> =
    store.backendType === 'bitcoind'
      ? { FM_BITCOIND_URL: 'http://bitcoind.embassy:8332' }
      : { FM_ESPLORA_URL: store.url || '' }

  /**
   * ======================== Daemons ========================
   *
   * In this section, we create one or more daemons that define the service runtime.
   *
   * Each daemon defines its own health check, which can optionally be exposed to the user.
   */
  return sdk.Daemons.of(effects, started).addDaemon('primary', {
    subcontainer: await sdk.SubContainer.of(
      effects,
      { imageId: 'fedimintd' },
      sdk.Mounts.of().mountVolume({
        volumeId: 'fedimintd',
        subpath: null,
        mountpoint: '/fedimintd',
        readonly: false,
      }),
      'fedimintd-sub',
    ),
    exec: {
      env,
      command: ['fedimintd', '--data-dir', '/fedimintd/'],
    },
    ready: {
      display: 'Web Interface',
      fn: () =>
        sdk.healthCheck.checkPortListening(effects, uiPort, {
          successMessage: 'The web interface is ready',
          errorMessage: 'The web interface is not ready',
        }),
    },
    requires: [],
  })
})

import { Variants } from '@start9labs/start-sdk/base/lib/actions/input/builder'
import { sdk } from '../sdk'
import { Patterns } from '@start9labs/start-sdk/base/lib/util'
import { storeJson } from '../fileModels/store.json'

const { InputSpec, Value } = sdk

export const inputSpec = InputSpec.of({
  backend: Value.union({
    name: 'Select Backend',
    default: 'bitcoind',
    variants: Variants.of({
      bitcoind: {
        name: 'Local Bitcoin Node',
        spec: InputSpec.of({}),
      },
      esplora: {
        name: 'External Esplora',
        spec: InputSpec.of({
          url: Value.text({
            name: 'Esplora API URL',
            default: 'https://mempool.space/api',
            required: true,
            inputmode: 'url',
            patterns: [Patterns.url],
          }),
        }),
      },
    }),
  }),
})

export const setBackend = sdk.Action.withInput(
  // id
  'set-backend',

  // metadata
  async ({ effects }) => ({
    name: 'Set Backend',
    description: 'Choose how Fedimint connects to the Bitcoin network',
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),

  // form input specification
  inputSpec,

  // optionally pre-fill the input form
  async ({ effects }) => {
    const store = await storeJson.read().once()

    if (!store) return {}

    return store.backendType === 'bitcoind'
      ? {
          backend: {
            selection: store.backendType,
            value: {},
          },
        }
      : {
          backend: {
            selection: store.backendType,
            value: { url: store.url },
          },
        }
  },

  // the execution function
  async ({ effects, input }) =>
    storeJson.merge(effects, {
      backendType: input.backend.selection,
      url:
        input.backend.selection === 'bitcoind'
          ? 'bitcoind.startos:8332'
          : input.backend.value.url,
    }),
)

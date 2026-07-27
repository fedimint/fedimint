import { FileHelper, matches } from '@start9labs/start-sdk'

const { object, string, literals } = matches

export const shape = object({
  backendType: literals('bitcoind', 'esplora').onMismatch('bitcoind'),
  url: string.optional().onMismatch(undefined),
})

// @TODO might be better
// export const shape = object({
//   backend: oneOf(
//     object({
//       backendType: literal('bitcoind'),
//     }),
//     object({
//       backendType: literal('esplora'),
//       url: string,
//     }),
//   ),
// })

export const storeJson = FileHelper.json(
  {
    volumeId: 'fedimintd',
    subpath: '/store.json',
  },
  shape,
)

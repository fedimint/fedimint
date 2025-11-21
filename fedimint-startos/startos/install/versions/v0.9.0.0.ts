import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'
import * as fs from 'fs/promises'
import { load } from 'js-yaml'
import { storeJson } from '../../fileModels/store.json'

export const v_0_9_0_0 = VersionInfo.of({
  version: '0.9.0:1',
  releaseNotes: 'Initial release for StartOS 0.4.0',
  migrations: {
    up: async ({ effects }) => {
      // get old config.yaml
      const configYaml = load(
        await fs.readFile(
          '/media/startos/volumes/main/start9/config.yaml',
          'utf-8',
        ),
      ) as
        | {
            'backend-type': 'bitcoind' | 'esplora'
            url: string
          }
        | undefined

      if (configYaml) {
        await storeJson.write(effects, {
          backendType: configYaml['backend-type'],
          url: configYaml.url,
        })
      }

      // @TODO make sure we can/need to delete the main volume here
      await fs
        .rm('/media/startos/volumes/main', { recursive: true })
        .catch(console.error)
    },
    down: IMPOSSIBLE,
  },
})

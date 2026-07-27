import { sdk } from './sdk'

export const { createBackup, restoreInit } = sdk.setupBackups(
  async ({ effects }) =>
    sdk.Backups.ofVolumes('fedimintd')
      .setOptions({
        exclude: ['database/'],
      })
      .setPostRestore(async (effects) => {
        // @TODO
      }),
)

import { setupManifest } from '@start9labs/start-sdk'
import { SDKImageInputSpec } from '@start9labs/start-sdk/base/lib/types/ManifestTypes'

const BUILD = process.env.BUILD || ''

const architectures =
  BUILD === 'x86_64' || BUILD === 'aarch64' ? [BUILD] : ['x86_64', 'aarch64']

export const manifest = setupManifest({
  id: 'fedimintd',
  title: 'Fedimint',
  license: 'MIT',
  wrapperRepo:
    'https://github.com/fedimint/fedimint/tree/master/fedimint-startos',
  upstreamRepo: 'https://github.com/fedimint/fedimint',
  supportSite: 'https://github.com/fedimint/fedimint/issues',
  marketingSite: 'https://fedimint.org/',
  donationUrl: null,
  docsUrl:
    'https://github.com/fedimint/fedimint/blob/master/fedimint-startos/docs/instructions.md',
  description: {
    short: 'Federated E-Cash Mint',
    long: 'Fedimint is a federated Chaumian E-Cash Mint to custody and transact bitcoin in a community.',
  },
  volumes: ['fedimintd'],
  images: {
    fedimintd: {
      source: { dockerTag: 'fedimint/fedimintd:v0.9.0' },
      arch: architectures,
    } as SDKImageInputSpec,
  },
  hardwareRequirements: {
    arch: architectures,
  },
  alerts: {
    install: null,
    update: null,
    uninstall: null,
    restore: null,
    start: null,
    stop: null,
  },
  dependencies: {
    bitcoind: {
      description:
        'Provides private, self-hosted blockchain data instead of relying on external Esplora APIs',
      optional: true,
      metadata: {
        title: 'Bitcoin',
        icon: 'https://bitcoin.org/img/icons/opengraph.png?1749679667',
      },
    },
  },
})

# Translating fedimint-ui

Our source language, i.e. the language we develop in, is English. Any missing translations will fall back to using the English translation. If you add text to the app, make sure not to use plain language in source files. Instead add any strings to the English translation file of the respective app:

`fedimint-ui/apps/gateway-ui/src/translation/en/gateway.json`

### Example

To begin you will need to add your choice of locale in the resources in the `@fedimint/translation` package as below.

i18n Index File:

```ts
// fedimint-ui/packages/translation/index.ts

import { gatewayTranslations } from '../../apps/gateway-ui/src/translations';
import { guardianTranslations } from '../../apps/guardian-ui/src/translations/';

const resources = {
  en: {
    gateway: gatewayTranslations.en,
    guardian: guardianTranslations.en,
  },
  ko: {
    gateway: gatewayTranslations.ko,
    guardian: guardianTranslations.ko,
  },
};
```

Then you may begin adding your own translations to test as you go.

Source File:

```tsx
// /apps/gateway-ui/src/component/HelloWorld.tsx
import { useTranslation } from '@fedimint/translation';

export cdefault function HelloWorldComponent() {
  const { t } = useTranslation('gateway');

  return <h1>{t('hello_world.heading')}</h1>
}
```

Translations Folder:

- Index File:

```ts
// /apps/gateway-ui/src/translations/
import en from './en.json';
import ko from './ko.json';

export const gatewayTranslations = {
  en,
  ko,
};
```

- Translation File:

```json
// /apps/gateway-ui/src/translations/ko.json
{
  "hello_world": {
    "heading": "안녕 세상!"
  },
  ...
}
```

### Adding a new language

To add a new language:

1. Look in the `/packages/translation` index to determine if there are any existing resource files for your preferred language.
1. If no translations in your language exist create the respective json file in the `/apps/{app}/src/translation/` folder of your language
1. Be sure to populate your language in the `resources` object in the `/packages/translation/index.ts` file for easy imports.
1. Open up the `{your-language}.json` file you just created and start translating!

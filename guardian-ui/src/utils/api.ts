import { AnyFedimintModule, ConfigGenParams } from '../types';

/**
 * Given a config and the name of the module, return the module
 */
export function getModuleParamsFromConfig<T extends AnyFedimintModule[0]>(
  config: ConfigGenParams | null,
  moduleName: T
  // Ignore any type below, it will be properly typed at call time via moduleName.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Extract<AnyFedimintModule, [T, any]>[1] | null {
  if (!config) return null;
  const module = Object.values(config.modules).find((m) => m[0] === moduleName);
  return module ? module[1] : null;
}

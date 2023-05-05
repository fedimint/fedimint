import { JsonRpcError } from 'jsonrpc-client-websocket';
import { AnyFedimintModule, ConfigGenParams, Peer } from '../types';

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

/**
 * Given an unknown error object, return a user-facing message.
 */
export function formatApiErrorMessage(err: unknown) {
  if (!err) return 'Unknown error';
  if ('error' in (err as { error: JsonRpcError })) {
    return (err as { error: JsonRpcError }).error.message;
  }
  if ('code' in (err as JsonRpcError)) {
    return (err as JsonRpcError).message;
  }
  if ('message' in (err as Error)) {
    return (err as Error).message;
  }
  return (err as object).toString();
}

/**
 * Given a map of peers, determine which one is you.
 */
export function getMyPeerId(peers: Record<string, Peer>) {
  // TODO: Find a better way to do this than using env var?
  const myApiUrl = new URL(process.env.REACT_APP_FM_CONFIG_API as string);
  return Object.entries(peers).find((peer) => {
    const apiUrl = new URL(peer[1].api_url);
    return myApiUrl.origin === apiUrl.origin;
  })?.[0];
}

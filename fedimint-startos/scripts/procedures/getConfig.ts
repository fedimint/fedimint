import { DEFAULT_RUST_LOG } from "../constants.ts";
import { types as T, compat } from "../deps.ts";

export const getConfig: T.ExpectedExports.getConfig = compat.getConfig({
  "fedimintd-bitcoin-backend": {
    type: "union",
    name: "Bitcoin Backend",
    description: "Choose how Fedimint connects to the Bitcoin network",
    "tag": {
      "id": "backend-type",
      "name": "Backend Type",
      "variant-names": {
        "bitcoind": "Bitcoin Core (Recommended)",
        "esplora": "Esplora"
      }
    },
    "default": "bitcoind",
    "variants": {
      "bitcoind": {
        "user": {
          type: "pointer",
          name: "RPC Username",
          description: "The username for Bitcoin Core's RPC interface",
          subtype: "package",
          "package-id": "bitcoind",
          target: "config",
          multi: false,
          selector: "$.rpc.username",
        },
        "password": {
          type: "pointer",
          name: "RPC Password",
          description: "The password for Bitcoin Core's RPC interface",
          subtype: "package",
          "package-id": "bitcoind",
          target: "config",
          multi: false,
          selector: "$.rpc.password",
        }
      },
      "esplora": {
        "url": {
          type: "string",
          name: "Esplora API URL",
          description: "The URL of the Esplora API to use (e.g., https://mempool.space/api)",
          nullable: false,
          default: "https://mempool.space/api",
          pattern: "^https?://.*",
          "pattern-description": "Must be a valid HTTP(S) URL"
        }
      }
    }
  },
  "advanced": {
    type: "object",
    name: "Advanced Settings",
    description: "Optional configuration for debugging and development",
    nullable: false,
    spec: {
      "rust-log-level": {
        type: "string",
        name: "Rust Log Directives",
        description: "Rust logging directives (e.g., 'info,fm=debug'). Only modify if debugging.",
        nullable: false,
        default: DEFAULT_RUST_LOG,
        pattern: ".*",
        "pattern-description": "Any valid Rust log directive string"
      }
    }
  }
});

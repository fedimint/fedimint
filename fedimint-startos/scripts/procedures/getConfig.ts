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
  "rust-log-level": {
    type: "enum",
    name: "Log Level",
    description: "Set the Rust logging verbosity for Fedimint. Higher levels provide more detailed logs but may impact performance.",
    values: ["error", "warn", "info", "debug", "trace"],
    "value-names": {
      "error": "Error - Only critical errors",
      "warn": "Warning - Errors and warnings",
      "info": "Info - Normal operational messages (Recommended)",
      "debug": "Debug - Detailed debugging information",
      "trace": "Trace - Very verbose, all events"
    },
    default: "info"
  }
});

import { DEFAULT_RUST_LOG } from "../constants.ts";
import { compat, types as T } from "../deps.ts";

export const migration: T.ExpectedExports.migration = compat.migrations.fromMapping(
  {
    "0.9.1": {
      up: compat.migrations.updateConfig(
        (config) => {
          if (!config.advanced) {
            config.advanced = {};
          }
          if (!config.advanced["rust-log-level"]) {
            config.advanced["rust-log-level"] = DEFAULT_RUST_LOG;
          }
          return config;
        },
        true,
        { version: "0.9.1", type: "up" }
      ),
      down: compat.migrations.updateConfig(
        (config) => config,
        true,
        { version: "0.9.1", type: "down" }
      ),
    },
  },
  "0.9.1"
);

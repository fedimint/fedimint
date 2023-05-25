module.exports = {
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react/recommended",
    "turbo",
    "prettier",
  ],
  plugins: ["@typescript-eslint"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  rules: {
    quotes: ["error", "single", { avoidEscape: true, allowTemplateLiterals: true  }],
    semi: ["error", "always", { omitLastInOneLineBlock: true }],
  },
  settings: {
    react: {
      version: "detect",
    },
  },
};

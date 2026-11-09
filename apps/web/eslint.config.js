import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "dangerouslySetInnerHTML is strictly forbidden by the security policy (PRD Section 9).",
        },
        {
          selector:
            "MemberExpression[object.name='Math'][property.name='random']",
          message:
            "Math.random is forbidden. Use crypto.getRandomValues instead (PRD Section 3).",
        },
      ],
    },
  }
);

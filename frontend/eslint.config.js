// ESLint flat config (eslint 9). 프론트 소스의 잠재 버그(미사용 변수, 잘못된 hook 의존성 등)를
// 커밋 전에 잡는 게이트. 스타일 강제는 최소화하고 '버그성' 규칙 위주로 켠다.
import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default [
  {
    ignores: ["dist/**", "node_modules/**", "playwright-report/**", "test-results/**"],
  },
  js.configs.recommended,

  // 앱 소스(브라우저 런타임)
  {
    files: ["src/**/*.{js,jsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { react, "react-hooks": reactHooks },
    settings: { react: { version: "detect" } },
    rules: {
      ...react.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      "react/react-in-jsx-scope": "off", // React 17+ 자동 JSX 런타임 — import React 불필요
      "react/prop-types": "off", // 이 프로젝트는 prop-types 를 쓰지 않는다
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },

  // 유닛/컴포넌트 테스트(vitest 심볼은 파일에서 import) — 브라우저+노드 글로벌 허용
  {
    files: ["src/**/*.{test,spec}.{js,jsx}", "vitest.setup.js"],
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
  },

  // e2e(playwright) + 설정 파일 — 노드 런타임(+ page.evaluate 콜백 안의 브라우저 글로벌 허용)
  {
    files: ["e2e/**/*.js", "*.config.js", "eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node, ...globals.browser },
    },
  },
];

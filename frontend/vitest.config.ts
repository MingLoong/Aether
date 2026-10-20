import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'path'
import { legacyTemplateI18nPlugin } from './src/i18n/legacy-template-transform'

export default defineConfig({
  // `includeAbsolute: false` 让模板里的绝对路径资源（如 `<img src="/aether_adaptive.svg">`）
  // **原样保留**，不再被编译成资源导入 ✓。
  //
  // 背景 ✗：这些图都放在 `public/` 下，本来就该按绝对 URL 用 ✓；但 `@vitejs/plugin-vue`
  // 默认会把静态 `src` 当资源导入处理 ✓，于是 `/aether_adaptive.svg` 被解析成
  // `file:///aether_adaptive.svg`，在 Windows 上 `fileURLToPath` 直接抛
  // 「The argument 'filename' must be a file URL object…」✗，
  // 导致 `LoginDialog.spec.ts` / `RegisterDialog.spec.ts` / `RegisterDialog.turnstile.spec.ts`
  // 三个文件在**收集阶段**就失败（0 条用例被执行 ✗）。Linux/CI 上同一步骤不会炸，
  // 所以只在本机暴露 —— 改这里只影响测试，生产构建（`vite.config.ts`）保持原样 ✓。
  plugins: [legacyTemplateI18nPlugin(), vue({ template: { transformAssetUrls: { includeAbsolute: false } } })],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/tests/vitest.setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.spec.ts',
        '**/*.d.ts',
        '**/vite.config.ts'
      ]
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})

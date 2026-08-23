import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ command }) => {
  const repo = process.env.GITHUB_REPOSITORY?.split('/')[1]
  const base =
    command === 'build'
      ? process.env.BASE_PATH || (repo ? `/${repo}/` : '/')
      : '/'

  return {
    plugins: [
      react(),
      {
        name: 'html-security-meta',
        apply: 'build',
        transformIndexHtml() {
          return [
            {
              tag: 'meta',
              attrs: {
                'http-equiv': 'Content-Security-Policy',
                content: "default-src 'self'; script-src 'self' https://stats.byreference.net; connect-src 'self' https://stats.byreference.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'",
              },
              injectTo: 'head-prepend',
            },
            {
              tag: 'meta',
              attrs: {
                name: 'referrer',
                content: 'strict-origin-when-cross-origin',
              },
              injectTo: 'head-prepend',
            },
          ]
        },
      },
    ],
    base,
    server: {
      host: '127.0.0.1',
    },
    css: {
      preprocessorOptions: {
        scss: {
          silenceDeprecations: ['import', 'global-builtin', 'color-functions', 'if-function'],
        },
      },
    },
    build: {
      outDir: 'dist',
      assetsDir: 'assets',
      emptyOutDir: true,
      chunkSizeWarningLimit: 1200,
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor-react': ['react', 'react-dom'],
            'vendor-icons': ['lucide-react'],
          },
        },
      },
    },
  }
})

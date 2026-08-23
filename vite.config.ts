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
          manualChunks(id) {
            if (id.includes('node_modules/react') || id.includes('node_modules/react-dom')) {
              return 'vendor-react';
            }
            if (id.includes('node_modules/lucide-react')) {
              return 'vendor-icons';
            }
            if (id.includes('incident_details_catalog') || id.includes('tool_details_catalog')) {
              return 'security-intelligence-db';
            }
            if (id.includes('data_saif') || id.includes('data_genai_data_security') || id.includes('data_secure_mcp_guide') || id.includes('data_ml') || id.includes('data_mcp')) {
              return 'frameworks-data';
            }
          },
        },
      },
    },
  }
})

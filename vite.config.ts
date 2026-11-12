import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { createHash } from 'node:crypto'

/** SHA-256 CSP source expressions for every inline <script> (no src) in the HTML. */
const inlineScriptHashes = (html: string): string[] =>
  [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)]
    .map((m) => m[1])
    .filter((body) => body.trim().length > 0)
    .map((body) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`)

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
        transformIndexHtml(html: string) {
          const isDev = command !== 'build';
          // Production: allow only our own inline analytics loader, pinned by hash (never 'unsafe-inline').
          const hashes = inlineScriptHashes(html).join(' ');
          const scriptSrc = isDev 
            ? "'self' 'unsafe-inline' https://stats.byreference.net" 
            : `'self' ${hashes ? hashes + ' ' : ''}https://stats.byreference.net`;
          const connectSrc = isDev
            ? "'self' https://stats.byreference.net ws: wss:"
            : "'self' https://stats.byreference.net";

          return [
            {
              tag: 'meta',
              attrs: {
                'http-equiv': 'Content-Security-Policy',
                content: `default-src 'self'; script-src ${scriptSrc}; connect-src ${connectSrc}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests`,
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
            {
              tag: 'meta',
              attrs: {
                'http-equiv': 'X-Content-Type-Options',
                content: 'nosniff',
              },
              injectTo: 'head-prepend',
            },
            {
              tag: 'meta',
              attrs: {
                'http-equiv': 'Permissions-Policy',
                content: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
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
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      },
    },
    preview: {
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      },
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
        // src/data/* modules are pure data literals. Declaring them side-effect free lets Rollup drop a
        // catalog (e.g. the multi-megabyte MITRE ATLAS dataset) from every chunk that merely re-imports the barrel.
        treeshake: {
          moduleSideEffects: (id) => !/[\\/]src[\\/]data[\\/]/.test(id),
        },
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
            if (
              id.includes('/data/data_tests') || id.includes('/data/data_agentic') || id.includes('/data/data_llm') ||
              id.includes('/data/data_red_teaming_manual') || id.includes('/data/tools_catalog') || id.includes('/data/incidents_catalog')
            ) {
              return 'catalog-data';
            }
            if (id.includes('data_mitre_atlas') && !id.includes('data_mitre_atlas_index')) {
              return 'mitre-atlas-data';
            }
            if (id.includes('data_saif') || id.includes('data_genai_data_security') || id.includes('data_secure_mcp_guide') || id.includes('data_ml') || id.includes('data_mcp') || id.includes('data_securing_agentic_apps')) {
              return 'frameworks-data';
            }
          },
        },
      },
    },
  }
})

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
    plugins: [react()],
    base,
    server: {
      host: true,
    },
    build: {
      outDir: 'dist',
      assetsDir: 'assets',
      emptyOutDir: true,
    },
  }
})

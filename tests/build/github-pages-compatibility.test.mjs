import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

function readFile(relativePath) {
  const fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) return '';
  return fs.readFileSync(fullPath, 'utf8');
}

test('Build - GitHub Pages Static Assets & Directory Structure', (t) => {
  const distDir = path.join(rootDir, 'dist');
  if (!fs.existsSync(distDir)) {
    execSync('npm run build', { cwd: rootDir, stdio: 'pipe' });
  }
  assert.ok(fs.existsSync(distDir), 'Production dist/ directory must exist');

  const indexHtml = readFile('dist/index.html');
  assert.ok(indexHtml.length > 0, 'dist/index.html must exist and not be empty');

  // Verify CSP meta tag injection in built HTML
  assert.ok(indexHtml.includes('http-equiv="Content-Security-Policy"'), 'dist/index.html must contain injected Content-Security-Policy meta header');
  assert.ok(indexHtml.includes('name="referrer" content="strict-origin-when-cross-origin"'), 'dist/index.html must contain strict-origin-when-cross-origin referrer header');

  // Verify assets directory
  const assetsDir = path.join(distDir, 'assets');
  assert.ok(fs.existsSync(assetsDir), 'dist/assets directory must exist');

  const assetFiles = fs.readdirSync(assetsDir);
  assert.ok(assetFiles.some(f => f.endsWith('.js')), 'dist/assets must contain bundled JS files');
  assert.ok(assetFiles.some(f => f.endsWith('.css')), 'dist/assets must contain bundled CSS files');
});

test('Build - Vite Dynamic Base Path Resolution for GitHub Pages', (t) => {
  const viteConfig = readFile('vite.config.ts');

  // Verify BASE_PATH and GITHUB_REPOSITORY handling
  assert.ok(viteConfig.includes('process.env.BASE_PATH'), 'vite.config.ts must support process.env.BASE_PATH');
  assert.ok(viteConfig.includes('process.env.GITHUB_REPOSITORY'), 'vite.config.ts must support process.env.GITHUB_REPOSITORY subpath extraction');
});

test('Build - Pure Static SPA Assertion (Zero Backend Server Code Leakage)', (t) => {
  const packageJson = JSON.parse(readFile('package.json'));

  // Ensure dependencies do not include server frameworks (express, fastify, etc.) in production dependencies
  const prodDeps = Object.keys(packageJson.dependencies || {});
  const forbiddenServerDeps = ['express', 'fastify', 'koa', 'nestjs', 'next', 'nuxt'];

  for (const dep of forbiddenServerDeps) {
    assert.ok(!prodDeps.includes(dep), `Production dependencies must not include server runtime: ${dep}`);
  }
});

/**
 * Security Tests — Software Supply Chain Integrity (CWE-1357 / SLSA Level 1)
 *
 * Verifies that the project follows supply chain security best practices:
 * dependency pinning, lock file presence, minimal production deps, safe lifecycle
 * scripts, and pinned GitHub Actions versions to prevent dependency confusion attacks.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

function readFile(relativePath) {
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(readFile(relativePath));
}

// ─── 1. Node.js Engine Version Pinning ───────────────────────────────────────

test('Supply Chain - package.json pins Node.js engine version', (t) => {
  const pkg = readJson('package.json');

  assert.ok(pkg.engines, 'package.json must declare an "engines" field');
  assert.ok(pkg.engines.node, 'package.json must pin a Node.js version in engines.node');

  // Must be specific (not * or "latest")
  assert.ok(
    pkg.engines.node !== '*' && pkg.engines.node !== 'latest',
    `engines.node must not be "*" or "latest". Found: "${pkg.engines.node}"`
  );

  t.diagnostic(`Node.js engine pinned to: ${pkg.engines.node}`);
});

// ─── 2. Lock File Presence ────────────────────────────────────────────────────

test('Supply Chain - package-lock.json exists for deterministic installs', (t) => {
  const lockPath = path.join(rootDir, 'package-lock.json');
  assert.ok(fs.existsSync(lockPath), 'package-lock.json must exist for reproducible builds and supply chain integrity');

  const lockStat = fs.statSync(lockPath);
  assert.ok(lockStat.size > 1000, 'package-lock.json must be non-trivial (>1KB) — a valid lock file');
});

// ─── 3. Minimal Production Dependencies ──────────────────────────────────────

test('Supply Chain - production dependencies are minimal (≤6 packages)', (t) => {
  const pkg = readJson('package.json');
  const prodDeps = Object.keys(pkg.dependencies || {});

  assert.ok(
    prodDeps.length <= 6,
    `Production dependencies should be minimal (≤6). Found ${prodDeps.length}: ${prodDeps.join(', ')}`
  );

  // Expected deps: react, react-dom, lucide-react, bootstrap
  const expectedDeps = ['react', 'react-dom', 'lucide-react', 'bootstrap'];
  for (const dep of expectedDeps) {
    assert.ok(
      prodDeps.includes(dep),
      `Expected production dependency "${dep}" must be present`
    );
  }

  t.diagnostic(`Production dependencies (${prodDeps.length}): ${prodDeps.join(', ')}`);
});

// ─── 4. Forbidden Server-Side Dependencies ────────────────────────────────────

test('Supply Chain - no server-framework dependencies in production (pure SPA)', (t) => {
  const pkg = readJson('package.json');
  const prodDeps = Object.keys(pkg.dependencies || {});

  const forbiddenServerDeps = [
    'express', 'fastify', 'koa', 'nestjs', '@nestjs/core',
    'next', 'nuxt', 'hapi', 'restify', 'polka'
  ];

  for (const dep of forbiddenServerDeps) {
    assert.ok(
      !prodDeps.includes(dep),
      `Production dependencies must not include server runtime: "${dep}" (this is a pure static SPA)`
    );
  }
});

// ─── 5. Lifecycle Script Safety ──────────────────────────────────────────────

test('Supply Chain - package.json has no dangerous lifecycle scripts (preinstall/postinstall)', (t) => {
  const pkg = readJson('package.json');
  const scripts = pkg.scripts || {};

  const dangerousLifecycles = ['preinstall', 'postinstall', 'prepack', 'prepare'];

  for (const lifecycle of dangerousLifecycles) {
    if (scripts[lifecycle] !== undefined) {
      // If defined, it should not execute arbitrary commands
      const scriptContent = scripts[lifecycle];
      assert.ok(
        !scriptContent.includes('curl') && !scriptContent.includes('wget') && !scriptContent.includes('fetch'),
        `Lifecycle script "${lifecycle}" must not download content: "${scriptContent}"`
      );
      assert.ok(
        !scriptContent.includes('rm -rf') && !scriptContent.includes('sudo'),
        `Lifecycle script "${lifecycle}" must not use dangerous shell commands: "${scriptContent}"`
      );
    }
  }

  t.diagnostic('No dangerous lifecycle scripts detected in package.json');
});

// ─── 6. GitHub Actions Version Pinning ───────────────────────────────────────

test('Supply Chain - GitHub Actions workflows use pinned action versions (not @latest)', (t) => {
  const workflowDir = path.join(rootDir, '.github/workflows');
  const workflowFiles = fs.readdirSync(workflowDir)
    .filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));

  assert.ok(workflowFiles.length > 0, 'At least one GitHub Actions workflow must exist');

  for (const file of workflowFiles) {
    const content = readFile(`.github/workflows/${file}`);

    // Check that actions don't use @latest
    const latestUsages = [...content.matchAll(/uses:\s*[^\s@]+@latest/g)].map(m => m[0]);
    assert.equal(
      latestUsages.length,
      0,
      `Workflow ${file} must not pin actions to @latest (supply chain risk): ${latestUsages.join(', ')}`
    );

    // Verify actions are pinned to specific major versions (e.g., @v3, @v4)
    const actionUsages = [...content.matchAll(/uses:\s*([^\s]+)/g)].map(m => m[1]);
    for (const action of actionUsages) {
      // Skip Docker images and local actions (./  prefix)
      if (action.startsWith('./') || action.startsWith('docker://')) continue;

      assert.ok(
        action.includes('@'),
        `Workflow ${file} must pin action "${action}" to a specific version tag (e.g., @v4)`
      );
    }
  }
});

// ─── 7. No Secrets in Source Files ───────────────────────────────────────────

test('Supply Chain - no hardcoded secrets or API keys in source TypeScript files', (t) => {
  const sourceFiles = [
    'App.tsx', 'index.tsx', 'data.ts', 'vite.config.ts',
    'data_tests.ts', 'data_llm.ts', 'data_ml.ts'
  ];

  // Common secret patterns
  const secretPatterns = [
    /\bsk-[A-Za-z0-9]{20,}\b/,          // OpenAI API key pattern
    /\bghp_[A-Za-z0-9]{36}\b/,          // GitHub personal access token
    /\bbearer\s+[A-Za-z0-9+/=]{20,}/i,  // Bearer token
    /\bpassword\s*=\s*["'][^"']{8,}["']/i, // Hardcoded password
    /\bAWSAccessKeyId\b/,                // AWS credentials
  ];

  for (const file of sourceFiles) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) continue;
    const content = fs.readFileSync(filePath, 'utf8');

    for (const pattern of secretPatterns) {
      assert.ok(
        !pattern.test(content),
        `Potential hardcoded secret found in ${file} matching pattern: ${pattern}`
      );
    }
  }
});

// ─── 8. .gitignore Guards Sensitive Artifacts ─────────────────────────────────

test('Supply Chain - .gitignore excludes node_modules, dist, and environment files', (t) => {
  const gitignorePath = path.join(rootDir, '.gitignore');
  assert.ok(fs.existsSync(gitignorePath), '.gitignore must exist');

  const content = fs.readFileSync(gitignorePath, 'utf8');

  assert.ok(content.includes('node_modules'), '.gitignore must exclude node_modules');
  assert.ok(content.includes('dist') || content.includes('/dist'), '.gitignore must exclude dist/ directory');

  // Optionally check for .env exclusion
  const excludesEnv = content.includes('.env') || content.includes('*.env');
  t.diagnostic(excludesEnv ? '.gitignore excludes .env files' : 'Note: .gitignore does not explicitly exclude .env files');
});

// ─── 9. Package Integrity: Private Flag ──────────────────────────────────────

test('Supply Chain - package.json is marked private to prevent accidental npm publish', (t) => {
  const pkg = readJson('package.json');

  assert.strictEqual(
    pkg.private,
    true,
    'package.json must have "private": true to prevent accidental npm publish of this internal codebase'
  );
});

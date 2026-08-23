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

test('Security - Content Security Policy (CSP) & Referrer Policy Configuration', (t) => {
  const viteConfig = readFile('vite.config.ts');

  // Verify CSP header presence
  assert.ok(viteConfig.includes("http-equiv': 'Content-Security-Policy'"), 'Vite config must inject Content-Security-Policy meta tag');
  assert.ok(viteConfig.includes("default-src 'self'"), 'CSP must restrict default-src to self');
  assert.ok(viteConfig.includes("object-src 'none'"), 'CSP must disallow object/plugins (object-src none)');
  assert.ok(viteConfig.includes("base-uri 'self'"), 'CSP must restrict base-uri to self');
  assert.ok(viteConfig.includes("form-action 'self'"), 'CSP must restrict form-action to self');
  
  // Verify Referrer header
  assert.ok(viteConfig.includes("strict-origin-when-cross-origin"), 'Vite config must inject strict-origin-when-cross-origin referrer policy');
});

test('Security - Test Payload Safe Rendering (Zero dangerouslySetInnerHTML for Payloads)', (t) => {
  const testDetail = readFile('components/TestDetail.tsx');
  const testList = readFile('components/TestList.tsx');
  const owaspView = readFile('components/OwaspTop10View.tsx');

  // Verify that test items are rendered without dangerous unescaped HTML injection
  assert.ok(!testDetail.includes('dangerouslySetInnerHTML'), 'TestDetail must not use dangerouslySetInnerHTML');
  assert.ok(!testList.includes('dangerouslySetInnerHTML'), 'TestList must not use dangerouslySetInnerHTML');
  assert.ok(!owaspView.includes('dangerouslySetInnerHTML'), 'OwaspTop10View must not use dangerouslySetInnerHTML');
});

test('Security - No Dynamic Code Execution (eval / Function constructor)', (t) => {
  const componentFiles = fs.readdirSync(path.join(rootDir, 'components'));

  for (const file of componentFiles) {
    if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      const code = readFile(`components/${file}`);
      assert.ok(!code.includes('eval('), `File components/${file} must not contain eval()`);
      assert.ok(!code.includes('new Function('), `File components/${file} must not contain new Function()`);
    }
  }
});

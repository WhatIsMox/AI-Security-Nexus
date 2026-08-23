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
  assert.ok(viteConfig.includes("upgrade-insecure-requests"), 'CSP must mandate upgrade-insecure-requests');
  
  // Verify Referrer header & additional security headers
  assert.ok(viteConfig.includes("strict-origin-when-cross-origin"), 'Vite config must inject strict-origin-when-cross-origin referrer policy');
  assert.ok(viteConfig.includes("X-Content-Type-Options"), 'Vite config must inject X-Content-Type-Options');
  assert.ok(viteConfig.includes("nosniff"), 'Vite config must mandate nosniff');
  assert.ok(viteConfig.includes("Permissions-Policy"), 'Vite config must inject Permissions-Policy');
});

test('Security - Global Zero-DOM-XSS Static Analysis (CWE-79)', (t) => {
  const componentFiles = fs.readdirSync(path.join(rootDir, 'components'));
  componentFiles.push('../App.tsx');
  componentFiles.push('../index.tsx');

  for (const file of componentFiles) {
    if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      const code = readFile(file.startsWith('../') ? file.replace('../', '') : `components/${file}`);
      
      // Assert zero usage of dangerous DOM injection primitives
      assert.ok(!code.includes('dangerouslySetInnerHTML'), `File ${file} must not contain dangerouslySetInnerHTML`);
      assert.ok(!code.includes('.innerHTML'), `File ${file} must not contain .innerHTML assignment`);
      assert.ok(!code.includes('.outerHTML'), `File ${file} must not contain .outerHTML assignment`);
      assert.ok(!code.includes('document.write('), `File ${file} must not contain document.write`);
      assert.ok(!code.includes('document.writeln('), `File ${file} must not contain document.writeln`);
    }
  }
});

test('Security - No Dynamic Code Execution (eval / Function constructor / String timers) (CWE-95)', (t) => {
  const componentFiles = fs.readdirSync(path.join(rootDir, 'components'));
  componentFiles.push('../App.tsx');
  componentFiles.push('../index.tsx');

  for (const file of componentFiles) {
    if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      const code = readFile(file.startsWith('../') ? file.replace('../', '') : `components/${file}`);
      assert.ok(!code.includes('eval('), `File ${file} must not contain eval()`);
      assert.ok(!code.includes('new Function('), `File ${file} must not contain new Function()`);
      
      // Ensure setTimeout/setInterval are called with functions, not string code
      const stringTimeoutRegex = /setTimeout\s*\(\s*["'`]/g;
      const stringIntervalRegex = /setInterval\s*\(\s*["'`]/g;
      assert.ok(!stringTimeoutRegex.test(code), `File ${file} must not pass raw string code to setTimeout`);
      assert.ok(!stringIntervalRegex.test(code), `File ${file} must not pass raw string code to setInterval`);
    }
  }
});

test('Security - Attack Payloads Isolated as Safe Text in Pre/Code Blocks (OWASP LLM Red-Teaming)', (t) => {
  const testDetailCode = readFile('components/TestDetail.tsx');
  const dashboardCode = readFile('components/Dashboard.tsx');

  // Verify payloads are rendered inside <pre> and <code> blocks
  assert.ok(testDetailCode.includes('<pre'), 'TestDetail must wrap payloads in <pre> tags');
  assert.ok(testDetailCode.includes('<code'), 'TestDetail must wrap payloads in <code> tags');
  assert.ok(dashboardCode.includes('<pre'), 'Dashboard spotlight must wrap sample payload in <pre> tag');
});

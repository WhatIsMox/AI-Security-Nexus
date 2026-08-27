import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

function readFile(relativePath) {
  let fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) {
    if (fs.existsSync(path.join(rootDir, 'src/data', relativePath))) {
      fullPath = path.join(rootDir, 'src/data', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src/components', relativePath))) {
      fullPath = path.join(rootDir, 'src/components', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src', relativePath))) {
      fullPath = path.join(rootDir, 'src', relativePath);
    }
  }
  return fs.readFileSync(fullPath, 'utf8');
}

test('Security - Tooling Catalog URL Validation', (t) => {
  const content = readFile('tools_catalog.ts');
  const urls = [...content.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);

  assert.ok(urls.length >= 100, `Expected at least 100 tool URLs, found ${urls.length}`);

  for (const u of urls) {
    assert.ok(u.startsWith('https://') || u.startsWith('http://'), `Tool URL must start with http/https: ${u}`);
    assert.ok(!u.includes('javascript:'), `Tool URL must not use javascript scheme: ${u}`);
    assert.ok(!u.includes('data:'), `Tool URL must not use data URI: ${u}`);
    assert.doesNotThrow(() => new URL(u), `Invalid URL format: ${u}`);
  }
});

test('Security - Framework Data Catalogs URL Validation', (t) => {
  const dataFiles = [
    'data_llm.ts',
    'data_ml.ts',
    'data_saif.ts',
    'data_mcp.ts',
    'data_agentic.ts',
    'data_agentic_applications.ts',
    'data_genai_data_security.ts',
    'data_secure_mcp_guide.ts',
    'data_tests.ts'
  ];

  let totalFrameworkUrls = 0;

  for (const df of dataFiles) {
    const content = readFile(df);
    const urls = [...content.matchAll(/https?:\/\/[^\s"'`<>)]+/g)].map(m => m[0]);
    totalFrameworkUrls += urls.length;

    for (const u of urls) {
      assert.ok(!u.includes('javascript:'), `URL in ${df} must not use javascript scheme: ${u}`);
      assert.ok(!u.includes('data:'), `URL in ${df} must not use data URI: ${u}`);
      assert.doesNotThrow(() => new URL(u), `Invalid URL in ${df}: ${u}`);
    }
  }

  assert.ok(totalFrameworkUrls > 0, `Expected framework data URLs, found ${totalFrameworkUrls}`);
  t.diagnostic(`Verified ${totalFrameworkUrls} framework data URLs`);
});

test('Security - Incidents Catalog URL Validation', (t) => {
  const content = readFile('incidents_catalog.ts');
  const urls = [...content.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);

  assert.ok(urls.length >= 150, `Expected at least 150 incident URLs, found ${urls.length}`);

  for (const u of urls) {
    assert.ok(u.startsWith('https://') || u.startsWith('http://'), `Incident citation URL must start with http/https: ${u}`);
    assert.ok(!u.includes('javascript:'), `Incident citation must not use javascript scheme: ${u}`);
    assert.doesNotThrow(() => new URL(u), `Invalid URL format: ${u}`);
  }
});


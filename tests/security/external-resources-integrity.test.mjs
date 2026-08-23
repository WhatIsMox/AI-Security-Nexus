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

test('Security - Incidents Catalog URL Validation', (t) => {
  const content = readFile('incidents_catalog.ts');
  const urls = [...content.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);

  assert.ok(urls.length >= 40, `Expected at least 40 incident URLs, found ${urls.length}`);

  for (const u of urls) {
    assert.ok(u.startsWith('https://') || u.startsWith('http://'), `Incident citation URL must start with http/https: ${u}`);
    assert.ok(!u.includes('javascript:'), `Incident citation must not use javascript scheme: ${u}`);
    assert.doesNotThrow(() => new URL(u), `Invalid URL format: ${u}`);
  }
});

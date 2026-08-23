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

function getAllFiles(dir, ext = ['.tsx', '.ts', '.html']) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      if (file !== 'node_modules' && file !== 'dist' && file !== '.git') {
        results = results.concat(getAllFiles(fullPath, ext));
      }
    } else if (ext.some(e => file.endsWith(e))) {
      results.push(fullPath);
    }
  }
  return results;
}

test('Security - Strict Reverse Tabnabbing Defense across all UI Components (CWE-1022)', (t) => {
  const componentFiles = getAllFiles(path.join(rootDir, 'components'));
  componentFiles.push(path.join(rootDir, 'App.tsx'));
  componentFiles.push(path.join(rootDir, 'index.html'));

  let totalBlankLinks = 0;

  for (const filePath of componentFiles) {
    const relPath = path.relative(rootDir, filePath);
    const content = fs.readFileSync(filePath, 'utf8');

    // Match all anchor tags <a ... >
    const anchorRegex = /<a\b([^>]*?)>/gi;
    let match;

    while ((match = anchorRegex.exec(content)) !== null) {
      const tagAttributes = match[1];

      // Check if target="_blank" is used
      if (/target\s*=\s*["']_blank["']/i.test(tagAttributes)) {
        totalBlankLinks++;
        
        // Assert rel="noopener noreferrer" or rel="noreferrer noopener" is present
        const hasNoopener = /rel\s*=\s*["'][^"']*\bnoopener\b[^"']*["']/i.test(tagAttributes);
        const hasNoreferrer = /rel\s*=\s*["'][^"']*\bnoreferrer\b[^"']*["']/i.test(tagAttributes);

        assert.ok(
          hasNoopener && hasNoreferrer,
          `Reverse Tabnabbing vulnerability in ${relPath}: target="_blank" must include rel="noopener noreferrer". Found: <a ${tagAttributes}>`
        );
      }
    }
  }

  assert.ok(totalBlankLinks > 0, `Expected target="_blank" external links, found ${totalBlankLinks}`);
  t.diagnostic(`Verified ${totalBlankLinks} target="_blank" links have strict rel="noopener noreferrer" protection.`);
});

test('Security - Disallow Dangerous URL Protocols across entire Codebase (CWE-79)', (t) => {
  const allSourceFiles = getAllFiles(rootDir, ['.tsx', '.ts', '.html', '.json']);

  const forbiddenProtocols = [
    'javascript:',
    'vbscript:',
    'data:text/html',
    'data:application/javascript'
  ];

  for (const filePath of allSourceFiles) {
    const relPath = path.relative(rootDir, filePath);
    
    // Skip test files that verify the presence of security checks
    if (relPath.startsWith('tests/')) continue;
    // Skip auto-generated stats or build config if not containing links
    if (relPath === 'package-lock.json') continue;

    const content = fs.readFileSync(filePath, 'utf8');

    for (const proto of forbiddenProtocols) {
      // Find occurrences of protocol outside comments/text descriptions if in href or src
      const hrefRegex = new RegExp(`(?:href|src)\\s*=\\s*["'\`][^"'\`]*${proto.replace(':', '\\:')}`, 'gi');
      assert.ok(
        !hrefRegex.test(content),
        `Dangerous protocol "${proto}" found in ${relPath}`
      );
    }
  }
});

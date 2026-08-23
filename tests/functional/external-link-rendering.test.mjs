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

test('Functional - External Link Component Rendering & Safety Attributes', (t) => {
  const components = [
    'components/IncidentsDirectoryView.tsx',
    'components/ToolsDirectoryView.tsx',
    'components/OwaspTop10View.tsx',
    'components/TestDetail.tsx',
    'components/SecureMcpGuideView.tsx',
    'components/GenAiDataSecurityView.tsx'
  ];

  for (const compPath of components) {
    const code = readFile(compPath);

    // Check if the component renders <a> tags for external links
    const anchorMatches = [...code.matchAll(/<a\s+[^>]*href=[^>]*>/gs)];
    
    if (anchorMatches.length > 0) {
      for (const match of anchorMatches) {
        const tag = match[0];
        // If it's an external link with target="_blank", ensure it enforces rel="noopener noreferrer" or rel="noreferrer"
        if (tag.includes('target="_blank"') || tag.includes("target='_blank'")) {
          assert.ok(
            tag.includes('rel="noopener noreferrer"') || tag.includes('rel="noreferrer"'),
            `Component ${compPath} has an external link missing 'rel="noopener noreferrer"': ${tag}`
          );
        }
      }
    }
  }
});

test('Functional - Incident & Tool Link Integrity and Resolution in UI Catalogs', (t) => {
  const incidentsCode = readFile('incidents_catalog.ts');
  const toolsCode = readFile('tools_catalog.ts');

  // Extract all URLs from incidents_catalog.ts
  const incidentUrls = [...incidentsCode.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);
  // Extract all URLs from tools_catalog.ts
  const toolUrls = [...toolsCode.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);

  assert.ok(incidentUrls.length >= 150, `Expected >= 150 incident citations, found ${incidentUrls.length}`);
  assert.ok(toolUrls.length >= 100, `Expected >= 100 tool URLs, found ${toolUrls.length}`);

  const allUrls = [...incidentUrls, ...toolUrls];
  const invalidPatterns = ['localhost', '127.0.0.1', 'example.com', 'placeholder', 'TODO', 'undefined', 'null'];

  for (const url of allUrls) {
    // 1. Must parse as valid URL
    let parsed;
    assert.doesNotThrow(() => {
      parsed = new URL(url);
    }, `Invalid URL format: "${url}"`);

    // 2. Must be https or http
    assert.ok(
      parsed.protocol === 'https:' || parsed.protocol === 'http:',
      `URL "${url}" must use https: or http: protocol`
    );

    // 3. Must not contain placeholder keywords
    for (const pattern of invalidPatterns) {
      assert.ok(
        !url.toLowerCase().includes(pattern),
        `URL "${url}" contains forbidden placeholder or test keyword: "${pattern}"`
      );
    }

    // 4. Hostname must contain valid TLD
    assert.ok(
      parsed.hostname.includes('.'),
      `URL "${url}" has invalid hostname without domain extension: "${parsed.hostname}"`
    );

    // 5. No malformed trailing punctuation
    assert.ok(!url.endsWith('"') && !url.endsWith("'") && !url.endsWith(",") && !url.endsWith(";"),
      `URL "${url}" has accidental trailing punctuation`
    );
  }
});

test('Functional - Threat Incident Mapping Minimum Density', (t) => {
  const incidentsCode = readFile('incidents_catalog.ts');
  
  // Verify INCIDENTS_BY_THREAT_ID mappings
  const threatMappingMatch = incidentsCode.match(/export const INCIDENTS_BY_THREAT_ID:\s*Record<string,\s*ExternalResource\[\]>\s*=\s*\{([\s\S]*?)\};/);
  assert.ok(threatMappingMatch, 'Could not find INCIDENTS_BY_THREAT_ID export in incidents_catalog.ts');

  const mappingBody = threatMappingMatch[1];
  const entries = [...mappingBody.matchAll(/["']([^"']+)["']:\s*([A-Z0-9_]+)/g)];

  assert.ok(entries.length >= 80, `Expected at least 80 threat mappings, found ${entries.length}`);

  for (const entry of entries) {
    const threatId = entry[1];
    const arrayName = entry[2];
    assert.ok(threatId.length >= 3, `Invalid threat ID format: ${threatId}`);
    assert.ok(arrayName.length >= 3, `Invalid incident array reference: ${arrayName}`);
  }
});

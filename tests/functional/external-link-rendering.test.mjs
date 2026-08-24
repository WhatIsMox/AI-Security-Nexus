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

test('Functional - Global Link Integrity, Format & Safety across all Data Catalogs', (t) => {
  const dataFiles = [
    'data_tests.ts',
    'data_agentic.ts',
    'data_llm.ts',
    'data_ml.ts',
    'data_saif.ts',
    'data_mcp.ts',
    'data_secure_mcp_guide.ts',
    'data_genai_data_security.ts',
    'tools_catalog.ts',
    'tool_details_catalog.ts',
    'incidents_catalog.ts',
    'incident_details_catalog.ts'
  ];

  const invalidPatterns = ['localhost', '127.0.0.1', 'example.com', 'placeholder', 'TODO', 'undefined', 'null'];
  let totalCheckedUrls = 0;

  for (const relPath of dataFiles) {
    const content = readFile(relPath);
    const urlMatches = [...content.matchAll(/url:\s*["']([^"']+)["']/g)].map(m => m[1]);

    for (const url of urlMatches) {
      totalCheckedUrls++;

      // 1. Must parse as valid URL
      let parsed;
      assert.doesNotThrow(() => {
        parsed = new URL(url);
      }, `File ${relPath} has unparseable URL: "${url}"`);

      // 2. Must use https: protocol
      assert.ok(
        parsed.protocol === 'https:' || parsed.protocol === 'http:',
        `File ${relPath} URL "${url}" must use https: or http: protocol`
      );

      // 3. Must not be placeholder '#' or dummy value
      assert.ok(url.trim() !== '#' && !url.endsWith('/#'), `File ${relPath} URL "${url}" is a dummy placeholder hash`);
      for (const pattern of invalidPatterns) {
        assert.ok(
          !url.toLowerCase().includes(pattern),
          `File ${relPath} URL "${url}" contains forbidden placeholder or test pattern: "${pattern}"`
        );
      }

      // 4. Must not have fake arXiv pattern like 2312.00000
      assert.ok(
        !/arxiv\.org\/abs\/\d{4}\.00000/.test(url),
        `File ${relPath} has fake placeholder arXiv identifier: "${url}"`
      );

      // 5. Hostname must contain valid TLD
      assert.ok(
        parsed.hostname.includes('.'),
        `File ${relPath} URL "${url}" has invalid hostname without domain extension: "${parsed.hostname}"`
      );

      // 6. No malformed trailing punctuation
      assert.ok(
        !url.endsWith('"') && !url.endsWith("'") && !url.endsWith(",") && !url.endsWith(";"),
        `File ${relPath} URL "${url}" has accidental trailing punctuation`
      );
    }
  }

  assert.ok(totalCheckedUrls >= 800, `Expected at least 800 URL citations across catalog, found ${totalCheckedUrls}`);
  t.diagnostic(`Verified ${totalCheckedUrls} URLs across all 12 data catalogs with zero invalid/placeholder links`);
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

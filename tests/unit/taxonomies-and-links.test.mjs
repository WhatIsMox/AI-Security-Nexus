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

test('Taxonomy - Test IDs Uniqueness & Formatting', (t) => {
  const standardTestsContent = readFile('data_tests.ts');
  const agenticTestsContent = readFile('data_agentic.ts');

  const standardIds = [...standardTestsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]);
  const agenticIds = [...agenticTestsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]);

  const allIds = [...standardIds, ...agenticIds];
  const uniqueIds = new Set(allIds);

  assert.equal(allIds.length, uniqueIds.size, `Duplicate test IDs detected: ${allIds.length} vs ${uniqueIds.size}`);

  for (const id of standardIds) {
    assert.match(id, /^AITG-(APP|MOD|INF|DAT|DATA|INFRA)-\d{2}$/, `Invalid standard test ID format: ${id}`);
  }
  for (const id of agenticIds) {
    assert.match(id, /^AGT-\d{2}$/, `Invalid agentic test ID format: ${id}`);
  }
});

test('Taxonomy - Pillar Mapping Validity', (t) => {
  const testsContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  const pillarMatches = [...testsContent.matchAll(/pillar:\s*Pillar\.([A-Z]+)/g)].map(m => m[1]);
  const agenticPillars = [...agenticContent.matchAll(/pillar:\s*Pillar\.([A-Z]+)/g)].map(m => m[1]);

  const allowedPillars = ['APP', 'MODEL', 'INFRA', 'DATA'];

  for (const p of [...pillarMatches, ...agenticPillars]) {
    assert.ok(allowedPillars.includes(p), `Invalid Pillar enum value used: Pillar.${p}`);
  }
});

test('Taxonomy - Cross-Framework References Resolution', (t) => {
  const llmContent = readFile('data_llm.ts');
  const agenticAppsContent = readFile('data_agentic_applications.ts');
  const saifContent = readFile('data_saif.ts');
  const testsContent = readFile('data_tests.ts');

  const validLlmIds = new Set([...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]));
  const validAsiIds = new Set([...agenticAppsContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]));
  const validSaifIds = new Set([...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]));

  const testLlmRefs = [...testsContent.matchAll(/owaspTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const testAsiRefs = [...testsContent.matchAll(/owaspAgenticRef:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const testSaifRefs = [...testsContent.matchAll(/owaspSaifRef:\s*["']([^"']+)["']/g)].map(m => m[1]);

  for (const ref of testLlmRefs) {
    assert.ok(validLlmIds.has(ref), `Test references unknown LLM ID: ${ref}`);
  }

  for (const ref of testAsiRefs) {
    assert.ok(validAsiIds.has(ref), `Test references unknown ASI ID: ${ref}`);
  }

  for (const ref of testSaifRefs) {
    assert.ok(validSaifIds.has(ref), `Test references unknown SAIF ID: ${ref}`);
  }
});

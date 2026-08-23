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

test('Functional - Threat Model SAIF Risks Structure', (t) => {
  const saifContent = readFile('data_saif.ts');
  
  // Verify SAIF IDs range from SAIF-R01 to SAIF-R15
  const saifIds = [...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]);
  assert.ok(saifIds.length >= 10, 'Expected at least 10 SAIF risk entries');
  assert.ok(saifIds.includes('SAIF-R01'), 'SAIF-R01 must exist');
  assert.ok(saifIds.includes('SAIF-R15'), 'SAIF-R15 must exist');

  assert.ok(saifContent.includes('OWASP_SAIF_THREATS_DATA'), 'Must export OWASP_SAIF_THREATS_DATA');
});

test('Functional - Threat Modeling Component SVG and Layers', (t) => {
  const threatModelingContent = readFile('components/ThreatModelling.tsx');

  // Verify that the 4 layers are represented
  assert.ok(threatModelingContent.includes('Application'), 'Must represent Application Layer');
  assert.ok(threatModelingContent.includes('Model'), 'Must represent Model Layer');
  assert.ok(threatModelingContent.includes('Data'), 'Must represent Data Layer');
  assert.ok(threatModelingContent.includes('Infrastructure'), 'Must represent Infrastructure Layer');

  // Verify interactive navigation callback presence
  assert.ok(threatModelingContent.includes('onNavigateToTest'), 'Must support navigation to linked test');
  assert.ok(threatModelingContent.includes('onNavigateToOwasp'), 'Must support navigation to OWASP risk');
});

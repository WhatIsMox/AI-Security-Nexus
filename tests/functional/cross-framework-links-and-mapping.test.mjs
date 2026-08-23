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

test('Cross-Framework - Complete ID Catalog Registry', (t) => {
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');
  const standardTestsContent = readFile('data_tests.ts');

  const llmIds = new Set([...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]));
  const mlIds = new Set([...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]));
  const asiIds = new Set([...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]));
  const astIds = new Set([...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]));
  const saifIds = new Set([...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]));
  const mcpIds = new Set([...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]));
  const dsgaiIds = new Set([...dsgaiContent.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1]));
  const dspmIds = new Set([...dsgaiContent.matchAll(/id:\s*["'](ai-dspm-\d{2})["']/g)].map(m => m[1]));

  const standardTestIds = new Set([...standardTestsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]));
  const agenticTestIds = new Set([...astContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]));
  const allTestIds = new Set([...standardTestIds, ...agenticTestIds]);

  assert.equal(llmIds.size, 10, 'Expected 10 LLM IDs');
  assert.equal(mlIds.size, 10, 'Expected 10 ML IDs');
  assert.equal(asiIds.size, 10, 'Expected 10 ASI IDs');
  assert.equal(astIds.size, 10, 'Expected 10 AST IDs');
  assert.equal(saifIds.size, 15, 'Expected 15 SAIF IDs');
  assert.equal(mcpIds.size, 10, 'Expected 10 MCP IDs');
  assert.equal(dsgaiIds.size, 21, 'Expected 21 DSGAI IDs');
  assert.equal(dspmIds.size, 13, 'Expected 13 AI-DSPM IDs');
  assert.equal(allTestIds.size, 42, 'Expected 42 total test items (32 standard + 10 agentic)');

  t.diagnostic(`Verified ${allTestIds.size} tests and 89 framework threat entries`);
});

test('Cross-Framework - Test Items Framework Cross-References Resolution', (t) => {
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const testsContent = readFile('data_tests.ts');

  const validLlmIds = new Set([...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]));
  const validMlIds = new Set([...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]));
  const validAgenticIds = new Set([
    ...[...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1])
  ]);
  const validSaifIds = new Set([...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]));
  const validMcpIds = new Set([...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]));

  // Extract all test references
  const llmRefs = [...testsContent.matchAll(/owaspTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const mlRefs = [...testsContent.matchAll(/owaspMlTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const agenticRefs = [...testsContent.matchAll(/owaspAgenticRef:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const saifRefs = [...testsContent.matchAll(/owaspSaifRef:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const mcpRefs = [...testsContent.matchAll(/owaspMcpTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);

  for (const ref of llmRefs) {
    assert.ok(validLlmIds.has(ref), `Test references unknown LLM ID: "${ref}"`);
  }
  for (const ref of mlRefs) {
    assert.ok(validMlIds.has(ref), `Test references unknown ML ID: "${ref}"`);
  }
  for (const ref of agenticRefs) {
    assert.ok(validAgenticIds.has(ref), `Test references unknown Agentic ID: "${ref}"`);
  }
  for (const ref of saifRefs) {
    assert.ok(validSaifIds.has(ref), `Test references unknown SAIF ID: "${ref}"`);
  }
  for (const ref of mcpRefs) {
    assert.ok(validMcpIds.has(ref), `Test references unknown MCP ID: "${ref}"`);
  }
});

test('Cross-Framework - Threat Modelling IDs and Related Tests Resolution', (t) => {
  const threatModelContent = readFile('components/ThreatModelling.tsx');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const testsContent = readFile('data_tests.ts');
  const agenticTestsContent = readFile('data_agentic.ts');

  const standardTestIds = new Set([...testsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]));
  const agenticTestIds = new Set([...agenticTestsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]));
  const allValidTestIds = new Set([...standardTestIds, ...agenticTestIds]);

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  // Extract all threat IDs defined in ThreatModelling datasets (SAIF, LLM, ML, ASI, AST, MCP)
  const threatIdMatches = [...threatModelContent.matchAll(/id:\s*["']((?:LLM|ML|ASI|AST|SAIF|MCP)[^"']+)["']/g)].map(m => m[1]);
  for (const tid of threatIdMatches) {
    assert.ok(allValidThreatIds.has(tid), `ThreatModelling defines threat with unknown canonical ID: "${tid}"`);
  }

  // Extract all relatedTestIds in ThreatModelling
  const matches = [...threatModelContent.matchAll(/relatedTestIds:\s*\[(.*?)\]/gs)];
  let checkedCount = 0;
  for (const match of matches) {
    const rawIds = match[1].split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean);
    for (const testId of rawIds) {
      assert.ok(allValidTestIds.has(testId), `ThreatModelling references unknown test ID: "${testId}"`);
      checkedCount++;
    }
  }

  assert.ok(checkedCount > 0, `Verified ${checkedCount} relatedTestIds links in ThreatModelling`);
});

test('Cross-Framework - Tools Catalog Threat IDs Resolution', (t) => {
  const toolsContent = readFile('tools_catalog.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  // Match keys in TOOLS_BY_THREAT_ID: 'LLM01:2026': [ ... ]
  const toolKeys = [...toolsContent.matchAll(/['"]([A-Za-z0-9_:\-]+)['"]\s*:\s*\[/g)].map(m => m[1]);
  for (const key of toolKeys) {
    assert.ok(allValidThreatIds.has(key), `Tools catalog maps to unknown threat ID: "${key}"`);
  }
});

test('Cross-Framework - Incidents Catalog Threat IDs Resolution', (t) => {
  const incidentsContent = readFile('incidents_catalog.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1])
  ]);

  const incidentKeys = [...incidentsContent.matchAll(/['"]([A-Za-z0-9_:\-]+)['"]\s*:\s*([A-Za-z0-9_]+)/g)].map(m => ({ id: m[1], varName: m[2] }));
  for (const { id } of incidentKeys) {
    assert.ok(allValidThreatIds.has(id), `Incidents catalog maps to unknown threat ID: "${id}"`);
  }

  // Verify all Top 10 framework threats are covered in the incident catalog
  const top10ThreatIds = [
    ...[...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1])
  ];

  const mappedIds = new Set(incidentKeys.map(k => k.id));
  for (const threatId of top10ThreatIds) {
    assert.ok(mappedIds.has(threatId), `Top 10 threat "${threatId}" must be mapped in incidents_catalog.ts`);
  }
});

test('Cross-Framework - GenAI Data Security Cross-References Validity', (t) => {
  const dsgaiContent = readFile('data_genai_data_security.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');

  const allValidIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  const crossRefMatches = [...dsgaiContent.matchAll(/crossReferences:\s*\[(.*?)\]/gs)];
  let verifiedEmbeddedCount = 0;

  for (const match of crossRefMatches) {
    const refs = match[1].split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean);
    for (const ref of refs) {
      // Find any embedded framework tokens (e.g. LLM04:2026, ASI03, AST02, DSGAI02, etc.)
      const embeddedIds = [...ref.matchAll(/\b(LLM\d{2}:\d{4}|ASI\d{2}|AST\d{2}|ML\d{2}:\d{4}|SAIF-R\d+|MCP\d+:\d{4}|DSGAI\d{2})\b/g)].map(m => m[1]);
      for (const embeddedId of embeddedIds) {
        assert.ok(allValidIds.has(embeddedId), `GenAI Data Security references unknown ID: "${embeddedId}" in string "${ref}"`);
        verifiedEmbeddedCount++;
      }
    }
  }

  assert.ok(verifiedEmbeddedCount > 0, `Verified ${verifiedEmbeddedCount} embedded framework IDs in GenAI Data Security cross-references`);
});

test('Cross-Framework - App Router Deep Linking Coverage for all Framework Prefixes', (t) => {
  const appContent = readFile('App.tsx');

  // Verify handleNavigateToOwasp handles all prefix families
  assert.ok(appContent.includes('id.startsWith("ML")'), 'Must route ML prefix');
  assert.ok(appContent.includes('id.startsWith("ASI")') || appContent.includes('id.startsWith("AST")'), 'Must route Agentic prefixes');
  assert.ok(appContent.includes('id.startsWith("SAIF")'), 'Must route SAIF prefix');
  assert.ok(appContent.includes('id.startsWith("MCP")'), 'Must route MCP prefix');
  assert.ok(appContent.includes('id.startsWith("DSGAI")') || appContent.includes('id.startsWith("ai-dspm")'), 'Must route GenAI Data Security prefix');
});

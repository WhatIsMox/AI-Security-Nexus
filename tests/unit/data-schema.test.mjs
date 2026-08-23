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

test('Unit - OWASP Top 10 for LLM Applications (2026) Schema Conformance', (t) => {
  const content = readFile('data_llm.ts');
  const ids = [...content.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]);
  
  assert.equal(ids.length, 10, 'Expected exactly 10 LLM Top 10 entries');
  assert.ok(ids.includes('LLM01:2026'), 'Should contain LLM01:2026');
  assert.ok(ids.includes('LLM10:2026'), 'Should contain LLM10:2026');

  // Verify presence of core properties
  assert.ok(content.includes('commonRisks:'), 'Entries must contain commonRisks');
  assert.ok(content.includes('preventionStrategies:'), 'Entries must contain preventionStrategies');
  assert.ok(content.includes('attackScenarios:'), 'Entries must contain attackScenarios');
  assert.ok(content.includes('references:'), 'Entries must contain references');
});

test('Unit - OWASP Machine Learning Top 10 Schema Conformance', (t) => {
  const content = readFile('data_ml.ts');
  const ids = [...content.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]);

  assert.equal(ids.length, 10, 'Expected exactly 10 ML Top 10 entries');
  assert.ok(ids.includes('ML01:2023'), 'Should contain ML01:2023');
  assert.ok(ids.includes('ML10:2023'), 'Should contain ML10:2023');
});

test('Unit - OWASP Agentic Applications (ASI01-ASI10) Schema Conformance', (t) => {
  const content = readFile('data_agentic_applications.ts');
  const ids = [...new Set([...content.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]))];

  assert.equal(ids.length, 10, 'Expected exactly 10 unique ASI entries');
  assert.ok(ids.includes('ASI01'), 'Should contain ASI01');
  assert.ok(ids.includes('ASI10'), 'Should contain ASI10');
  assert.ok(content.includes('AGENTIC_APPLICATIONS_OVERVIEW'), 'Must export AGENTIC_APPLICATIONS_OVERVIEW');
});

test('Unit - OWASP Agentic Skills (AST01-AST10) Schema Conformance', (t) => {
  const content = readFile('data_agentic.ts');
  const ids = [...new Set([...content.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]))];

  assert.equal(ids.length, 10, 'Expected exactly 10 unique AST entries');
  assert.ok(ids.includes('AST01'), 'Should contain AST01');
  assert.ok(ids.includes('AST10'), 'Should contain AST10');
  assert.ok(content.includes('AGENTIC_SKILLS_OVERVIEW'), 'Must export AGENTIC_SKILLS_OVERVIEW');
});

test('Unit - OWASP MCP Top 10 & Hardening Guide Schema Conformance', (t) => {
  const mcpContent = readFile('data_mcp.ts');
  const guideContent = readFile('data_secure_mcp_guide.ts');

  const mcpIds = [...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]);
  assert.equal(mcpIds.length, 10, 'Expected exactly 10 MCP Top 10 entries');
  assert.ok(mcpIds.includes('MCP1:2025'));
  assert.ok(mcpIds.includes('MCP10:2025'));

  assert.ok(guideContent.includes('SECURE_MCP_GUIDE_META'), 'Guide must contain SECURE_MCP_GUIDE_META');
  assert.ok(guideContent.includes('SECURE_MCP_GUIDE_SECTIONS'), 'Guide must contain SECURE_MCP_GUIDE_SECTIONS');
  assert.ok(guideContent.includes('SECURE_MCP_MINIMUM_BAR'), 'Guide must contain SECURE_MCP_MINIMUM_BAR');
});

test('Unit - OWASP GenAI Data Security (DSGAI01-DSGAI21 & AI-DSPM) Schema Conformance', (t) => {
  const content = readFile('data_genai_data_security.ts');
  const dsgaiIds = [...new Set([...content.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1]))];
  const dspmIds = [...new Set([...content.matchAll(/id:\s*["'](ai-dspm-\d{2})["']/g)].map(m => m[1]))];

  assert.equal(dsgaiIds.length, 21, 'Expected exactly 21 DSGAI entries (DSGAI01-DSGAI21)');
  assert.equal(dspmIds.length, 13, 'Expected exactly 13 AI-DSPM capability entries (ai-dspm-01 to ai-dspm-13)');
  assert.ok(content.includes('GENAI_DATA_SECURITY_META'), 'Must export metadata');
  assert.ok(content.includes('GENAI_DATA_SECURITY_OVERVIEW'), 'Must export overview');
});

test('Unit - Security Test Catalogs (AITG-* and AGT-*) Conformance', (t) => {
  const standardTestsContent = readFile('data_tests.ts');
  const agenticTestsContent = readFile('data_agentic.ts');

  const standardIds = [...standardTestsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]);
  const agenticIds = [...agenticTestsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]);

  assert.ok(standardIds.length >= 30, `Expected at least 30 standard AITG tests, found ${standardIds.length}`);
  assert.equal(agenticIds.length, 10, `Expected 10 agentic AGT tests, found ${agenticIds.length}`);

  const total = standardIds.length + agenticIds.length;
  assert.ok(total >= 40, `Expected at least 40 total security tests, found ${total}`);
});

test('Unit - AI Security Tooling Matrix Full Metadata Catalog Completeness', (t) => {
  const toolsCatalogContent = readFile('tools_catalog.ts');
  const toolDetailsContent = readFile('tool_details_catalog.ts');

  const toolNameMatches = [...toolsCatalogContent.matchAll(/name:\s*["\x27]([^"\x27]+)["\x27]/g)].map(m => m[1]);
  const uniqueToolNames = [...new Set(toolNameMatches)];

  assert.ok(uniqueToolNames.length >= 60, `Expected at least 60 unique tools, found ${uniqueToolNames.length}`);

  const dbMatches = [...toolDetailsContent.matchAll(/"([^"]+)":\s*\{/g)].map(m => m[1].toLowerCase());
  const dbSet = new Set(dbMatches);
  const missing = uniqueToolNames.filter(name => !dbSet.has(name.toLowerCase()));
  assert.equal(missing.length, 0, `All tools must have verified entries in TOOL_DATABASE. Missing: ${missing.join(', ')}`);

  // Assert presence of mandatory rich metadata fields across the database
  const requiredFields = ['longDescription', 'typicalUseCase', 'keyFeatures', 'installationOrQuickstart', 'license', 'authorOrMaintainer', 'ecosystem'];
  for (const field of requiredFields) {
    const matches = (toolDetailsContent.match(new RegExp(`${field}:\\s*`, 'g')) || []).length;
    assert.ok(matches >= uniqueToolNames.length, `Expected at least ${uniqueToolNames.length} '${field}' definitions in tool_details_catalog.ts, found ${matches}`);
  }
});

test('Unit - Real-World Incidents & Case Studies Full Metadata Completeness', (t) => {
  const incidentsCatalogContent = readFile('incidents_catalog.ts');
  const incidentDetailsContent = readFile('incident_details_catalog.ts');

  const incidentTitles = [...incidentsCatalogContent.matchAll(/title:\s*(?:"([^"]+)"|\x27([^\x27]+)\x27)/g)].map(m => m[1] || m[2]);
  const uniqueTitles = [...new Set(incidentTitles)];

  assert.ok(uniqueTitles.length >= 100, `Expected at least 100 unique incidents, found ${uniqueTitles.length}`);

  const dbMatches = [...incidentDetailsContent.matchAll(/"([^"]+)":\s*\{/g)].map(m => m[1].toLowerCase());
  const dbSet = new Set(dbMatches);

  const missing = uniqueTitles.filter(title => !dbSet.has(title.toLowerCase()));
  assert.equal(missing.length, 0, `All incidents must have verified entries in INCIDENT_DATABASE. Missing: ${missing.join(', ')}`);

  // Assert presence of mandatory fields
  const requiredFields = ['attackVector', 'impact', 'recoveryTime', 'repercussions', 'remediation', 'lessonsLearned', 'year', 'targetOrVictim', 'severity'];
  for (const field of requiredFields) {
    const matches = (incidentDetailsContent.match(new RegExp(`"${field}":\\s*`, 'g')) || []).length;
    assert.ok(matches >= uniqueTitles.length, `Expected at least ${uniqueTitles.length} '${field}' definitions in incident_details_catalog.ts, found ${matches}`);
  }
});




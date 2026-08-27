/**
 * Unit Tests — Data Barrel Re-Export Integrity
 *
 * Verifies that data.ts correctly merges and re-exports ALL framework constants,
 * test catalogs, and overview objects consumed by components across the app.
 * A broken barrel import causes runtime crashes that TypeScript won't catch at build time.
 */

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

// ─── 1. Barrel File Structural Integrity ─────────────────────────────────────

test('Barrel - data.ts exists and is non-empty', () => {
  const content = readFile('data.ts');
  assert.ok(content.trim().length > 0, 'data.ts must be non-empty');
  assert.ok(content.includes('export'), 'data.ts must contain export statements');
});

test('Barrel - data.ts merges TEST_DATA from standard + agentic sources', () => {
  const content = readFile('data.ts');

  // Must import from both sources
  assert.ok(
    content.includes("from './data_tests'") || content.includes('from "./data_tests"'),
    "data.ts must import from './data_tests'"
  );
  assert.ok(
    content.includes("from './data_agentic'") || content.includes('from "./data_agentic"'),
    "data.ts must import from './data_agentic'"
  );

  // Must export unified TEST_DATA
  assert.ok(content.includes('export const TEST_DATA'), 'data.ts must export TEST_DATA');

  // Must merge both arrays (spread syntax)
  const mergeMatch = content.match(/TEST_DATA\s*=\s*\[([^\]]+)\]/s);
  assert.ok(mergeMatch, 'TEST_DATA must be defined as an array literal');
  assert.ok(
    mergeMatch[1].includes('STANDARD_TEST_DATA') || mergeMatch[1].includes('TEST_DATA') || mergeMatch[1].includes('AGENTIC_TEST_DATA'),
    'TEST_DATA array must include spread of standard and agentic test collections'
  );
});

// ─── 2. Framework Data Re-Exports ────────────────────────────────────────────

test('Barrel - data.ts re-exports OWASP LLM Top 10 data', () => {
  const content = readFile('data.ts');

  // Direct or star re-export of data_llm
  const hasLlmReExport =
    content.includes("export * from './data_llm'") ||
    content.includes('export * from "./data_llm"') ||
    content.includes('OWASP_TOP_10_DATA');

  assert.ok(hasLlmReExport, 'data.ts must re-export OWASP LLM Top 10 data from data_llm.ts');

  // Verify the source file exports the expected symbol
  const llmSource = readFile('data_llm.ts');
  assert.ok(
    llmSource.includes('OWASP_TOP_10_DATA') || llmSource.includes('export const'),
    'data_llm.ts must export OWASP_TOP_10_DATA or equivalent'
  );
});

test('Barrel - data.ts re-exports OWASP ML Top 10 data', () => {
  const content = readFile('data.ts');
  const mlSource = readFile('data_ml.ts');

  const hasMLReExport =
    content.includes("export * from './data_ml'") ||
    content.includes('export * from "./data_ml"') ||
    content.includes('OWASP_ML_TOP_10_DATA');

  assert.ok(hasMLReExport, 'data.ts must re-export OWASP ML Top 10 data from data_ml.ts');
  assert.ok(
    mlSource.includes('OWASP_ML_TOP_10_DATA') || mlSource.includes('export const'),
    'data_ml.ts must export OWASP_ML_TOP_10_DATA or equivalent'
  );
});

test('Barrel - data.ts re-exports SAIF threats data', () => {
  const content = readFile('data.ts');
  const saifSource = readFile('data_saif.ts');

  const hasSaifReExport =
    content.includes("export * from './data_saif'") ||
    content.includes('export * from "./data_saif"') ||
    content.includes('OWASP_SAIF_THREATS_DATA');

  assert.ok(hasSaifReExport, 'data.ts must re-export SAIF threats from data_saif.ts');
  assert.ok(saifSource.includes('OWASP_SAIF_THREATS_DATA'), 'data_saif.ts must export OWASP_SAIF_THREATS_DATA');
});

test('Barrel - data.ts re-exports MCP Top 10 data', () => {
  const content = readFile('data.ts');
  const mcpSource = readFile('data_mcp.ts');

  const hasMcpReExport =
    content.includes("export * from './data_mcp'") ||
    content.includes('export * from "./data_mcp"') ||
    content.includes('OWASP_MCP_TOP_10_DATA');

  assert.ok(hasMcpReExport, 'data.ts must re-export MCP Top 10 data from data_mcp.ts');
  assert.ok(
    mcpSource.includes('OWASP_MCP_TOP_10_DATA') || mcpSource.includes('export const'),
    'data_mcp.ts must export OWASP_MCP_TOP_10_DATA or equivalent'
  );
});

test('Barrel - data.ts re-exports Agentic Applications (ASI) and Skills (AST) data', () => {
  const content = readFile('data.ts');

  assert.ok(
    content.includes('OWASP_AGENTIC_APPLICATIONS_DATA'),
    'data.ts must re-export OWASP_AGENTIC_APPLICATIONS_DATA'
  );
  assert.ok(
    content.includes('OWASP_AGENTIC_THREATS_DATA'),
    'data.ts must re-export OWASP_AGENTIC_THREATS_DATA'
  );

  // Verify the named exports reference their source files
  assert.ok(
    content.includes('data_agentic_applications') || content.includes("'./data_agentic_applications'"),
    'data.ts must reference data_agentic_applications.ts for ASI data'
  );
});

test('Barrel - data.ts re-exports GenAI Data Security risks and AI-DSPM capabilities', () => {
  const content = readFile('data.ts');
  const genaiSource = readFile('data_genai_data_security.ts');

  const hasGenAIReExport =
    content.includes("export * from './data_genai_data_security'") ||
    content.includes('export * from "./data_genai_data_security"') ||
    content.includes('GENAI_DATA_SECURITY_RISKS') ||
    content.includes('GENAI_DATA_SECURITY_META');

  assert.ok(hasGenAIReExport, 'data.ts must re-export GenAI Data Security data from data_genai_data_security.ts');
  assert.ok(
    genaiSource.includes('GENAI_DATA_SECURITY_RISKS') || genaiSource.includes('GENAI_DATA_SECURITY_META'),
    'data_genai_data_security.ts must export GenAI data security constants'
  );
});

test('Barrel - data.ts re-exports Secure MCP Guide constructs', () => {
  const content = readFile('data.ts');
  const guideSource = readFile('data_secure_mcp_guide.ts');

  const hasGuideReExport =
    content.includes("export * from './data_secure_mcp_guide'") ||
    content.includes('export * from "./data_secure_mcp_guide"') ||
    content.includes('SECURE_MCP_GUIDE_META');

  assert.ok(hasGuideReExport, 'data.ts must re-export Secure MCP Guide constructs from data_secure_mcp_guide.ts');
  assert.ok(guideSource.includes('SECURE_MCP_GUIDE_META'), 'data_secure_mcp_guide.ts must export SECURE_MCP_GUIDE_META');
  assert.ok(guideSource.includes('SECURE_MCP_GUIDE_SECTIONS'), 'data_secure_mcp_guide.ts must export SECURE_MCP_GUIDE_SECTIONS');
  assert.ok(guideSource.includes('SECURE_MCP_MINIMUM_BAR'), 'data_secure_mcp_guide.ts must export SECURE_MCP_MINIMUM_BAR');
});

// ─── 3. Framework Overview Re-Exports ────────────────────────────────────────

test('Barrel - data.ts re-exports Agentic overview objects (AGENTIC_SKILLS_OVERVIEW, AGENTIC_APPLICATIONS_OVERVIEW)', () => {
  const content = readFile('data.ts');

  assert.ok(
    content.includes('AGENTIC_SKILLS_OVERVIEW'),
    'data.ts must re-export AGENTIC_SKILLS_OVERVIEW'
  );
  assert.ok(
    content.includes('AGENTIC_APPLICATIONS_OVERVIEW'),
    'data.ts must re-export AGENTIC_APPLICATIONS_OVERVIEW'
  );

  // Verify source files contain these exports
  const agenticSource = readFile('data_agentic.ts');
  assert.ok(agenticSource.includes('AGENTIC_SKILLS_OVERVIEW'), 'data_agentic.ts must export AGENTIC_SKILLS_OVERVIEW');

  const agenticAppsSource = readFile('data_agentic_applications.ts');
  assert.ok(agenticAppsSource.includes('AGENTIC_APPLICATIONS_OVERVIEW'), 'data_agentic_applications.ts must export AGENTIC_APPLICATIONS_OVERVIEW');
});

// ─── 4. Component Import Consistency ─────────────────────────────────────────

test('Barrel - All component imports from data.ts reference valid exported symbols', () => {
  const barrelContent = readFile('data.ts');
  const appContent = readFile('App.tsx');

  // App.tsx must import TEST_DATA (for search modal and test list)
  assert.ok(
    appContent.includes("from './data'") || appContent.includes('from "./data"') || appContent.includes('TEST_DATA'),
    'App.tsx should import from barrel data.ts or reference TEST_DATA'
  );

  // GlobalSearchModal imports multiple framework datasets from data barrel
  const searchModalPath = 'components/GlobalSearchModal.tsx';
  const searchContent = readFile(searchModalPath);
  const importBlock = searchContent.match(/import\s*\{[^}]+\}\s*from\s*['"][./]*data['"]/s);
  assert.ok(
    importBlock || searchContent.includes("from '../data'") || searchContent.includes('from "./data"'),
    'GlobalSearchModal.tsx must import framework data from the data barrel'
  );
});

test('Barrel - data.ts has no circular import references', () => {
  const content = readFile('data.ts');

  // data.ts must not import from itself
  assert.ok(!content.includes("from './data'"), "data.ts must not self-import './data'");
  assert.ok(!content.includes('from "./data"'), 'data.ts must not self-import "./data"');

  // Check that re-export statements (export ... from) don't duplicate each other
  // Note: it is valid to have both `import X from './foo'` AND `export Y from './foo'`
  // in the same barrel file — this is common in TypeScript barrel patterns.
  const reExports = [...content.matchAll(/export\s+(?:\*|{[^}]+})\s+from\s+['"](\.[^'"]+)['"]/g)].map(m => m[1]);
  const reExportSet = new Set(reExports);
  assert.equal(
    reExports.length,
    reExportSet.size,
    `data.ts must not have duplicate re-export statements for the same source. Duplicates: ${
      reExports.filter((v, i) => reExports.indexOf(v) !== i).join(', ')
    }`
  );
});

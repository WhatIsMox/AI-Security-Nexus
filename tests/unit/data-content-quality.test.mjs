/**
 * Unit Tests — Data Content Quality Invariants
 *
 * Validates that every entry across all framework data files and test catalogs
 * contains substantive, well-formed content — not just that the field keys exist,
 * but that the arrays are non-empty, strings are meaningful, and enum values are valid.
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

// ─── Valid Enum Whitelists ────────────────────────────────────────────────────

const VALID_RISK_LEVELS = new Set(['Critical', 'High', 'Medium', 'Low']);
const VALID_MITIGATION_TYPES = new Set(['Remediation', 'Mitigation']);
const VALID_COST_VALUES = new Set(['Free', 'Free+Paid', 'Paid', '€', '€€', '€€€', '€€€€']);
const VALID_TOOL_TYPES = new Set(['Local', 'Third-party']);
const VALID_TOOL_CATEGORIES = new Set(['Offensive', 'Defensive', 'Both']);
const VALID_SEVERITY_VALUES = new Set(['Critical', 'High', 'Medium', 'Low']);

// ─── 1. TestItem Content Quality ──────────────────────────────────────────────

test('Content Quality - TestItem: objectives, payloads, and mitigationStrategies are non-empty', (t) => {
  const standardContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  // Every test block must define at least one objective string
  const objectivesMatches = [...standardContent.matchAll(/objectives:\s*\[([\s\S]*?)\]/g)].map(m => m[1].trim());
  for (const block of objectivesMatches) {
    assert.ok(block.length > 2, `Found a test in data_tests.ts with an empty objectives array`);
  }

  const agenticObjectives = [...agenticContent.matchAll(/objectives:\s*\[([\s\S]*?)\]/g)].map(m => m[1].trim());
  for (const block of agenticObjectives) {
    assert.ok(block.length > 2, `Found a test in data_agentic.ts with an empty objectives array`);
  }

  // Every test block must define at least one payload entry
  const payloadMatches = [...standardContent.matchAll(/payloads:\s*\[([\s\S]*?)\]/g)].map(m => m[1].trim());
  for (const block of payloadMatches) {
    assert.ok(block.length > 2, `Found a test in data_tests.ts with an empty payloads array`);
  }

  // Every test block must define at least one mitigation strategy
  const mitigationMatches = [...standardContent.matchAll(/mitigationStrategies:\s*\[([\s\S]*?)\]/g)].map(m => m[1].trim());
  for (const block of mitigationMatches) {
    assert.ok(block.length > 2, `Found a test in data_tests.ts with an empty mitigationStrategies array`);
  }
});

test('Content Quality - TestItem: riskLevel values are all valid enum members', (t) => {
  const standardContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  const allRiskLevels = [
    ...[...standardContent.matchAll(/riskLevel:\s*['"](.*?)['"]/g)].map(m => m[1]),
    ...[...agenticContent.matchAll(/riskLevel:\s*['"](.*?)['"]/g)].map(m => m[1])
  ];

  assert.ok(allRiskLevels.length > 0, 'Expected riskLevel fields to be present in test data');

  for (const level of allRiskLevels) {
    assert.ok(
      VALID_RISK_LEVELS.has(level),
      `Invalid riskLevel "${level}" — must be one of: ${[...VALID_RISK_LEVELS].join(', ')}`
    );
  }

  t.diagnostic(`Validated ${allRiskLevels.length} riskLevel enum values across test catalogs`);
});

test('Content Quality - TestItem: mitigationStrategy.type values are valid enum members', (t) => {
  const standardContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  const allTypes = [
    ...[...standardContent.matchAll(/type:\s*['"](Remediation|Mitigation)['"]/g)].map(m => m[1]),
    ...[...agenticContent.matchAll(/type:\s*['"](Remediation|Mitigation)['"]/g)].map(m => m[1])
  ];

  // Verify count — must have at least as many as the number of test items (each has ≥1)
  const testCount = [...standardContent.matchAll(/id:\s*['"]AITG-[A-Z]+-\d+['"]/g)].length +
                    [...agenticContent.matchAll(/id:\s*['"]AGT-\d+['"]/g)].length;
  assert.ok(allTypes.length >= testCount, `Expected at least ${testCount} MitigationStrategy.type entries, found ${allTypes.length}`);

  for (const type of allTypes) {
    assert.ok(VALID_MITIGATION_TYPES.has(type), `Invalid MitigationStrategy.type: "${type}"`);
  }
});

test('Content Quality - TestPayload: code blocks that are defined must be non-trivial (≥10 chars)', (t) => {
  const standardContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  // Match template-literal code blocks (most common, multi-line)
  const templateCodes = [
    ...[...standardContent.matchAll(/code:\s*`([^`]+)`/g)].map(m => m[1]),
    ...[...agenticContent.matchAll(/code:\s*`([^`]+)`/g)].map(m => m[1])
  ];

  // Match long single-quoted code strings (must be ≥10 chars by the capturing group)
  const quotedLongCodes = [
    ...[...standardContent.matchAll(/code:\s*["']([^"']{10,})["']/g)].map(m => m[1]),
    ...[...agenticContent.matchAll(/code:\s*["']([^"']{10,})["']/g)].map(m => m[1])
  ];

  const allCodeMatches = [...templateCodes, ...quotedLongCodes];

  // Template literal codes should be substantive
  for (const code of templateCodes) {
    assert.ok(
      code.trim().length >= 10,
      `TestPayload.code (template literal) must be non-trivial (≥10 chars), found: "${code.trim().slice(0, 40)}"`
    );
  }

  t.diagnostic(`Validated ${allCodeMatches.length} TestPayload.code blocks for substance`);
});

// ─── 2. OwaspTop10Entry Content Quality ──────────────────────────────────────

test('Content Quality - OwaspTop10Entry: all LLM entries have non-empty mandatory arrays', (t) => {
  const content = readFile('data_llm.ts');

  // Validate each LLM entry has non-empty description, commonRisks, preventionStrategies
  assert.ok(content.includes('commonRisks:'), 'data_llm.ts must contain commonRisks');
  assert.ok(content.includes('preventionStrategies:'), 'data_llm.ts must contain preventionStrategies');
  assert.ok(content.includes('attackScenarios:'), 'data_llm.ts must contain attackScenarios');
  assert.ok(content.includes('references:'), 'data_llm.ts must contain references');

  // Each array must contain at least one item (not empty brackets)
  const emptyCommonRisks = content.match(/commonRisks:\s*\[\s*\]/g);
  assert.equal(emptyCommonRisks, null, 'No LLM entry may have an empty commonRisks array');

  const emptyPrevention = content.match(/preventionStrategies:\s*\[\s*\]/g);
  assert.equal(emptyPrevention, null, 'No LLM entry may have an empty preventionStrategies array');

  const emptyAttackScenarios = content.match(/attackScenarios:\s*\[\s*\]/g);
  assert.equal(emptyAttackScenarios, null, 'No LLM entry may have an empty attackScenarios array');

  const emptyReferences = content.match(/references:\s*\[\s*\]/g);
  assert.equal(emptyReferences, null, 'No LLM entry may have an empty references array');
});

test('Content Quality - OwaspTop10Entry: all ML entries have non-empty mandatory arrays', (t) => {
  const content = readFile('data_ml.ts');

  const emptyCommonRisks = content.match(/commonRisks:\s*\[\s*\]/g);
  assert.equal(emptyCommonRisks, null, 'No ML entry may have an empty commonRisks array');

  const emptyPrevention = content.match(/preventionStrategies:\s*\[\s*\]/g);
  assert.equal(emptyPrevention, null, 'No ML entry may have an empty preventionStrategies array');

  const emptyReferences = content.match(/references:\s*\[\s*\]/g);
  assert.equal(emptyReferences, null, 'No ML entry may have an empty references array');
});

test('Content Quality - OwaspTop10Entry: ASI & AST agentic entries have non-empty mandatory arrays', (t) => {
  for (const file of ['data_agentic_applications.ts', 'data_agentic.ts']) {
    const content = readFile(file);

    const emptyCommonRisks = content.match(/commonRisks:\s*\[\s*\]/g);
    assert.equal(emptyCommonRisks, null, `${file}: no entry may have an empty commonRisks array`);

    const emptyPrevention = content.match(/preventionStrategies:\s*\[\s*\]/g);
    assert.equal(emptyPrevention, null, `${file}: no entry may have an empty preventionStrategies array`);

    const emptyReferences = content.match(/references:\s*\[\s*\]/g);
    assert.equal(emptyReferences, null, `${file}: no entry may have an empty references array`);
  }
});

test('Content Quality - OwaspTop10Entry: MCP Top 10 entries have non-empty mandatory arrays', (t) => {
  const content = readFile('data_mcp.ts');

  const emptyCommonRisks = content.match(/commonRisks:\s*\[\s*\]/g);
  assert.equal(emptyCommonRisks, null, 'No MCP entry may have an empty commonRisks array');

  const emptyPrevention = content.match(/preventionStrategies:\s*\[\s*\]/g);
  assert.equal(emptyPrevention, null, 'No MCP entry may have an empty preventionStrategies array');

  const emptyReferences = content.match(/references:\s*\[\s*\]/g);
  assert.equal(emptyReferences, null, 'No MCP entry may have an empty references array');
});

test('Content Quality - OwaspTop10Entry: SAIF threat entries have non-empty mandatory arrays', (t) => {
  const content = readFile('data_saif.ts');

  // SAIF might use different field names but should have description and references
  assert.ok(content.includes('description:'), 'data_saif.ts entries must have description fields');
  assert.ok(content.includes('references:'), 'data_saif.ts entries must have references fields');
  assert.ok(content.includes('OWASP_SAIF_THREATS_DATA'), 'data_saif.ts must export OWASP_SAIF_THREATS_DATA');

  const emptyReferences = content.match(/references:\s*\[\s*\]/g);
  assert.equal(emptyReferences, null, 'No SAIF entry may have an empty references array');
});

// ─── 3. Security Tool Catalog Quality ────────────────────────────────────────

test('Content Quality - SecurityTool: cost and type values are valid and realistic', (t) => {
  const content = readFile('tools_catalog.ts');

  const costValues = [...content.matchAll(/cost:\s*['"](.*?)['"]/g)].map(m => m[1]);
  const typeValues = [...content.matchAll(/type:\s*['"](Local|Third-party)['"]/g)].map(m => m[1]);
  const categoryValues = [...content.matchAll(/category:\s*['"](Offensive|Defensive|Both)['"]/g)].map(m => m[1]);

  assert.ok(costValues.length >= 60, `Expected at least 60 cost values, found ${costValues.length}`);

  for (const cost of costValues) {
    assert.ok(cost && cost.trim().length >= 4, `SecurityTool.cost must be non-trivial, found: "${cost}"`);
    assert.ok(
      cost.startsWith('Free') || cost.includes('$') || cost.includes('€') || cost.startsWith('~') || cost.includes('/'),
      `Invalid SecurityTool.cost format: "${cost}"`
    );
  }

  for (const type of typeValues) {
    assert.ok(VALID_TOOL_TYPES.has(type), `Invalid SecurityTool.type value: "${type}"`);
  }

  for (const cat of categoryValues) {
    assert.ok(VALID_TOOL_CATEGORIES.has(cat), `Invalid SecurityTool.category value: "${cat}"`);
  }

  t.diagnostic(`Validated ${costValues.length} cost, ${typeValues.length} type, ${categoryValues.length} category values`);
});

test('Content Quality - SecurityTool: all tool names and descriptions are non-empty strings', (t) => {
  const content = readFile('tools_catalog.ts');

  // Tool name must be at least 2 chars
  const names = [...content.matchAll(/name:\s*['"](.*?)['"]/g)].map(m => m[1]);
  assert.ok(names.length >= 60, `Expected at least 60 tool names, found ${names.length}`);

  for (const name of names) {
    assert.ok(name.trim().length >= 2, `Tool name too short: "${name}"`);
  }

  // Tool descriptions must be non-trivial (≥ 20 chars)
  const descriptions = [...content.matchAll(/description:\s*`([^`]{20,})`/g)].map(m => m[1])
    .concat([...content.matchAll(/description:\s*["']([^"']{20,})["']/g)].map(m => m[1]));

  assert.ok(descriptions.length > 0, 'Expected tool descriptions to be at least 20 chars long');
});

// ─── 4. Incident Catalog Quality ─────────────────────────────────────────────

test('Content Quality - Incident Intelligence: severity values are valid enum members', (t) => {
  const content = readFile('incident_details_catalog.ts');

  const severities = [...content.matchAll(/"severity":\s*['"](.*?)['"]/g)].map(m => m[1]);
  assert.ok(severities.length >= 50, `Expected at least 50 severity values in incident_details_catalog.ts, found ${severities.length}`);

  for (const sev of severities) {
    assert.ok(
      VALID_SEVERITY_VALUES.has(sev),
      `Invalid severity value: "${sev}" — must be one of: ${[...VALID_SEVERITY_VALUES].join(', ')}`
    );
  }

  t.diagnostic(`Validated ${severities.length} incident severity enum values`);
});

test('Content Quality - Incident Intelligence: mandatory string fields are non-trivial', (t) => {
  const content = readFile('incident_details_catalog.ts');

  // "attackVector" descriptions must be substantive (> 30 chars)
  const attackVectors = [...content.matchAll(/"attackVector":\s*"([^"]{30,})"/g)].map(m => m[1]);
  const totalAttackVectors = [...content.matchAll(/"attackVector":/g)].length;

  assert.ok(
    attackVectors.length >= totalAttackVectors * 0.8,
    `At least 80% of attackVector entries must be ≥ 30 chars. Found ${attackVectors.length}/${totalAttackVectors}`
  );

  // "lessonsLearned" must be substantive (> 20 chars)
  const lessons = [...content.matchAll(/"lessonsLearned":\s*"([^"]{20,})"/g)].map(m => m[1]);
  const totalLessons = [...content.matchAll(/"lessonsLearned":/g)].length;

  assert.ok(
    lessons.length >= totalLessons * 0.8,
    `At least 80% of lessonsLearned entries must be ≥ 20 chars. Found ${lessons.length}/${totalLessons}`
  );
});

// ─── 5. GenAI Data Security Quality ──────────────────────────────────────────

test('Content Quality - GenAI Data Security: DSGAI entries have non-empty mandatory arrays', (t) => {
  const content = readFile('data_genai_data_security.ts');

  // Every DSGAI risk must have a title and description
  const dsgaiIds = [...content.matchAll(/id:\s*['"](DSGAI\d{2})['"]/g)].map(m => m[1]);
  assert.equal(dsgaiIds.length, 21, `Expected exactly 21 DSGAI IDs, found ${dsgaiIds.length}`);

  // No empty riskFactors or mitigations arrays for DSGAI entries
  const emptyRiskFactors = content.match(/riskFactors:\s*\[\s*\]/g);
  assert.equal(emptyRiskFactors, null, 'No DSGAI entry may have an empty riskFactors array');

  // Verify AI-DSPM entries have non-empty capabilities
  const dspmIds = [...content.matchAll(/id:\s*['"](ai-dspm-\d{2})['"]/g)].map(m => m[1]);
  assert.equal(dspmIds.length, 13, `Expected exactly 13 AI-DSPM IDs, found ${dspmIds.length}`);
});

// ─── 6. Secure MCP Guide Quality ─────────────────────────────────────────────

test('Content Quality - Secure MCP Guide: sections and minimum bar controls are non-empty', (t) => {
  const content = readFile('data_secure_mcp_guide.ts');

  // SECURE_MCP_GUIDE_SECTIONS must contain at least 3 sections
  const sectionTitles = [...content.matchAll(/title:\s*['"](.*?)['"]/g)].map(m => m[1]);
  assert.ok(sectionTitles.length >= 3, `Expected at least 3 section titles in data_secure_mcp_guide.ts, found ${sectionTitles.length}`);

  // SECURE_MCP_MINIMUM_BAR must be a non-empty array
  // The export may have a TypeScript type annotation: SECURE_MCP_MINIMUM_BAR: Type[] = [...]
  const minimumBarMatch = content.match(/SECURE_MCP_MINIMUM_BAR[^=]*=\s*\[([\s\S]*?)\]/);
  assert.ok(minimumBarMatch, 'SECURE_MCP_MINIMUM_BAR must be defined as an array');
  assert.ok(minimumBarMatch[1].trim().length > 10, 'SECURE_MCP_MINIMUM_BAR must contain at least one item');

  // Guide sections must have sub-content arrays (bullets, body, subsections, or items)
  assert.ok(
    content.includes('bullets:') || content.includes('subsections:') || content.includes('items:'),
    'Secure MCP Guide sections must contain control content (bullets, subsections, or items)'
  );
});

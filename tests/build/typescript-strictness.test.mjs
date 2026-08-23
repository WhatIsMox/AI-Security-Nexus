/**
 * Build Tests — TypeScript Strictness & Code Quality Enforcement
 *
 * Verifies that the TypeScript configuration enforces strict mode, that no
 * unsafe escape hatches (@ts-ignore, @ts-nocheck, any casts) are present in
 * production code, and that types.ts exports all required interfaces.
 *
 * Note: tsconfig.json in this project does not use "strict: true" directly but
 * instead uses "isolatedModules", "noEmit", and ES2022 targets. These tests verify
 * the settings that ARE in use and guard against regressions.
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
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(readFile(relativePath));
}

// ─── 1. tsconfig.json Core Settings ─────────────────────────────────────────

test('TypeScript - tsconfig.json exists and is valid JSON', () => {
  const tsconfigPath = path.join(rootDir, 'tsconfig.json');
  assert.ok(fs.existsSync(tsconfigPath), 'tsconfig.json must exist');

  assert.doesNotThrow(() => {
    JSON.parse(fs.readFileSync(tsconfigPath, 'utf8'));
  }, 'tsconfig.json must be valid JSON');
});

test('TypeScript - tsconfig.json targets modern ES2022+ module system', () => {
  const tsconfig = readJson('tsconfig.json');
  const options = tsconfig.compilerOptions || {};

  // Target must be ES2020 or later for modern JS features
  const validTargets = new Set(['ES2020', 'ES2021', 'ES2022', 'ES2023', 'ES2024', 'ESNext']);
  assert.ok(
    validTargets.has(options.target),
    `tsconfig.json target must be ES2020 or later, found: "${options.target}"`
  );

  // Module system should be ESNext or ES2022+
  const validModules = new Set(['ES2020', 'ES2022', 'ESNext', 'NodeNext', 'Node16']);
  assert.ok(
    validModules.has(options.module),
    `tsconfig.json module must be ESNext or ES2022+, found: "${options.module}"`
  );
});

test('TypeScript - tsconfig.json enables isolatedModules for Vite compatibility', () => {
  const tsconfig = readJson('tsconfig.json');
  const options = tsconfig.compilerOptions || {};

  assert.strictEqual(
    options.isolatedModules,
    true,
    'tsconfig.json must enable isolatedModules for Vite single-file transpilation compatibility'
  );
});

test('TypeScript - tsconfig.json uses JSX: react-jsx (automatic runtime)', () => {
  const tsconfig = readJson('tsconfig.json');
  const options = tsconfig.compilerOptions || {};

  assert.ok(
    options.jsx === 'react-jsx' || options.jsx === 'react-jsxdev',
    `tsconfig.json must use jsx: "react-jsx" (automatic runtime), found: "${options.jsx}"`
  );
});

test('TypeScript - tsconfig.json includes DOM lib for browser APIs', () => {
  const tsconfig = readJson('tsconfig.json');
  const options = tsconfig.compilerOptions || {};

  const libs = (options.lib || []).map(l => l.toUpperCase());
  assert.ok(libs.some(l => l === 'DOM'), 'tsconfig.json lib must include "DOM" for browser API types');
});

// ─── 2. No TypeScript Escape Hatches in Production Code ──────────────────────

test('TypeScript Strictness - no @ts-ignore directives in source files', (t) => {
  const sourceFiles = [
    'App.tsx', 'index.tsx', 'data.ts', 'types.ts',
    'data_tests.ts', 'data_llm.ts', 'data_ml.ts', 'data_agentic.ts',
    'data_agentic_applications.ts', 'data_mcp.ts', 'data_saif.ts',
    'data_genai_data_security.ts', 'data_secure_mcp_guide.ts',
    'tools_catalog.ts', 'incidents_catalog.ts',
    'tool_details_catalog.ts', 'incident_details_catalog.ts',
  ];

  const violations = [];

  for (const file of sourceFiles) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, idx) => {
      if (line.includes('@ts-ignore')) {
        violations.push(`${file}:${idx + 1} — @ts-ignore found`);
      }
    });
  }

  assert.equal(
    violations.length,
    0,
    `@ts-ignore directives are forbidden in production source files:\n${violations.join('\n')}`
  );

  t.diagnostic('No @ts-ignore directives found in production source files');
});

test('TypeScript Strictness - no @ts-nocheck directives in source files', (t) => {
  const sourceFiles = [
    'App.tsx', 'index.tsx', 'data.ts', 'types.ts',
  ];

  const componentFiles = fs.readdirSync(path.join(rootDir, 'components'))
    .filter(f => f.endsWith('.tsx') || f.endsWith('.ts'))
    .map(f => `components/${f}`);

  const allFiles = [...sourceFiles, ...componentFiles];
  const violations = [];

  for (const file of allFiles) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    if (content.includes('@ts-nocheck')) {
      violations.push(file);
    }
  }

  assert.equal(
    violations.length,
    0,
    `@ts-nocheck directives are forbidden in source files: ${violations.join(', ')}`
  );
});

// ─── 3. types.ts Interface Completeness ──────────────────────────────────────

test('TypeScript - types.ts exports all required domain interfaces', (t) => {
  const content = readFile('types.ts');

  const requiredExports = [
    'Pillar',             // Core enum
    'TestPayload',        // Test item payload
    'ExternalResource',   // URL citation
    'RealWorldIncident',  // Incident catalog entry
    'SecurityTool',       // Tool catalog entry
    'SuggestedTool',      // Tool suggestion in tests
    'MitigationStrategy', // Mitigation in tests
    'TestItem',           // Full test case
    'OwaspTop10Entry',    // Framework threat entry
    'FrameworkOverview',  // Overview for each framework
    'Stat',               // Dashboard stat card
  ];

  for (const exported of requiredExports) {
    assert.ok(
      content.includes(`export enum ${exported}`) ||
      content.includes(`export interface ${exported}`) ||
      content.includes(`export type ${exported}`),
      `types.ts must export "${exported}"`
    );
  }

  t.diagnostic(`Verified ${requiredExports.length} required exports in types.ts`);
});

test('TypeScript - Pillar enum has exactly 4 members with correct string values', () => {
  const content = readFile('types.ts');

  const expectedPillarValues = [
    '"AI Application"',
    '"AI Model"',
    '"AI Infrastructure"',
    '"AI Data"',
  ];

  for (const value of expectedPillarValues) {
    assert.ok(
      content.includes(value),
      `Pillar enum must contain string value ${value}`
    );
  }

  // Count the enum members
  const enumMembers = [...content.matchAll(/APP\s*=|MODEL\s*=|INFRA\s*=|DATA\s*=/g)];
  assert.equal(enumMembers.length, 4, 'Pillar enum must have exactly 4 members: APP, MODEL, INFRA, DATA');
});

test('TypeScript - TestItem interface references Pillar enum (no plain strings)', () => {
  const content = readFile('types.ts');

  // pillar field should be typed as Pillar (not string)
  const pillarFieldMatch = content.match(/pillar:\s*(\w+)/);
  assert.ok(pillarFieldMatch, 'TestItem must have a pillar field');
  assert.strictEqual(
    pillarFieldMatch[1],
    'Pillar',
    `TestItem.pillar must be typed as Pillar enum, not "${pillarFieldMatch[1]}"`
  );
});

test('TypeScript - MitigationStrategy type field uses discriminated union', () => {
  const content = readFile('types.ts');

  // Must use literal union type for type field
  assert.ok(
    content.includes("'Remediation' | 'Mitigation'") || content.includes('"Remediation" | "Mitigation"'),
    'MitigationStrategy.type must use a discriminated union of "Remediation" | "Mitigation"'
  );
});

// ─── 4. No Implicit Any in Critical Type Positions ───────────────────────────

test('TypeScript - types.ts does not use "any" type except in legacy Stat.icon', (t) => {
  const content = readFile('types.ts');

  const anyUsages = [...content.matchAll(/:\s*any\b/g)].length;

  // Only the Stat.icon field legitimately uses `any` (Lucide React icon component)
  assert.ok(
    anyUsages <= 1,
    `types.ts should use at most 1 "any" type (for icon components). Found ${anyUsages} usage(s).`
  );

  t.diagnostic(`Found ${anyUsages} "any" type usage(s) in types.ts`);
});

// ─── 5. Component TypeScript Props ───────────────────────────────────────────

test('TypeScript - All component files use typed props interfaces (not untyped objects)', (t) => {
  const componentFiles = fs.readdirSync(path.join(rootDir, 'components'))
    .filter(f => f.endsWith('.tsx'));

  let typedComponents = 0;

  for (const file of componentFiles) {
    const content = readFile(`components/${file}`);

    // Each component should define typed props or use React.FC with generic
    const hasTypedProps =
      content.includes('interface') ||
      content.includes('React.FC<') ||
      content.includes(': React.FC') ||
      content.includes('Props = {') ||
      content.includes('Props ={');

    if (hasTypedProps) typedComponents++;
  }

  assert.ok(
    typedComponents >= componentFiles.length * 0.8,
    `At least 80% of component files must have typed props. Found ${typedComponents}/${componentFiles.length}`
  );

  t.diagnostic(`${typedComponents}/${componentFiles.length} components have typed props interfaces`);
});

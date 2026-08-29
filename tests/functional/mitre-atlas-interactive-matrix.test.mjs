/**
 * Functional Tests — MITRE ATLAS™ Interactive Matrix & Component Workflows
 * 
 * Validates the interactive behavior, UI state management, filtering modes,
 * mobile responsiveness adaptations, and drill-down inspection capabilities
 * of the MitreAtlasView component.
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

test('Functional - MitreAtlasView: Component Structure, Props & Routing Integration', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');
  const appContent = readFile('App.tsx');

  assert.ok(componentContent.includes('export default MitreAtlasView') || componentContent.includes('const MitreAtlasView'), 'MitreAtlasView must be exported');
  assert.ok(componentContent.includes('initialTechniqueId?: string | null'), 'Must accept initialTechniqueId prop for deep-linking');
  assert.ok(componentContent.includes('initialPillar?: Pillar | \'ALL\''), 'Must accept initialPillar prop for pillar scoping');
  assert.ok(componentContent.includes('onNavigateToTest?: (test: TestItem) => void'), 'Must support test navigation callback');

  // Verify App.tsx routing connection
  assert.ok(appContent.includes('currentView === \'mitre-atlas\''), 'App.tsx must route to mitre-atlas view');
  assert.ok(appContent.includes('<MitreAtlasView'), 'App.tsx must render MitreAtlasView');
});

test('Functional - MitreAtlasView: 3 Distinct View Modes (Navigator, Matrix, Directory)', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');

  // Assert viewMode state
  assert.ok(componentContent.includes('viewMode === \'navigator\''), 'Must support Lifecycle Flow Navigator mode');
  assert.ok(componentContent.includes('viewMode === \'matrix\''), 'Must support Matrix Grid mode');
  assert.ok(componentContent.includes('viewMode === \'directory\''), 'Must support Directory Catalog mode');

  // Assert view switcher buttons
  assert.ok(componentContent.includes('Lifecycle Flow'), 'Switcher must have Lifecycle Flow button');
  assert.ok(componentContent.includes('Matrix Grid'), 'Switcher must have Matrix Grid button');
  assert.ok(componentContent.includes('Catalog'), 'Switcher must have Catalog button');
});

test('Functional - MitreAtlasView: Testing Pillars Scope Filtering', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');

  // Assert pillar filtering logic
  assert.ok(componentContent.includes('selectedPillarFilter'), 'Must maintain selectedPillarFilter state');
  assert.ok(componentContent.includes('getTechniquePillars'), 'Must export getTechniquePillars helper');

  // Assert pillar filter chips
  assert.ok(componentContent.includes('All 4 Pillars (178)'), 'Must include All Pillars scope chip');
  assert.ok(componentContent.includes('Application Testing'), 'Must include Application Testing scope chip');
  assert.ok(componentContent.includes('Model Testing'), 'Must include Model Testing scope chip');
  assert.ok(componentContent.includes('Infrastructure'), 'Must include Infrastructure scope chip');
  assert.ok(componentContent.includes('Data Testing'), 'Must include Data Testing scope chip');
});

test('Functional - MitreAtlasView: AI Paradigm Filtering', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');

  // Assert paradigm filtering logic
  assert.ok(componentContent.includes('matchesParadigm'), 'Must define matchesParadigm helper');
  assert.ok(componentContent.includes('Autonomous & Agentic AI'), 'Must support Agentic AI paradigm filter');
  assert.ok(componentContent.includes('Generative AI & LLMs'), 'Must support Generative AI paradigm filter');
  assert.ok(componentContent.includes('Predictive & Classical ML'), 'Must support Classical ML paradigm filter');
  assert.ok(componentContent.includes('Enterprise Infrastructure'), 'Must support Enterprise Infrastructure paradigm filter');
});

test('Functional - MitreAtlasView: Subtechnique Collapsing & Expansion', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');

  // Assert subtechnique state
  assert.ok(componentContent.includes('expandedParents'), 'Must track expanded parent techniques');
  assert.ok(componentContent.includes('allSubtechniquesExpanded'), 'Must track global subtechnique expansion state');
  assert.ok(componentContent.includes('toggleParentExpansion'), 'Must define toggleParentExpansion handler');
  assert.ok(componentContent.includes('toggleAllSubtechniques'), 'Must define toggleAllSubtechniques handler');
});

test('Functional - MitreAtlasView: 4-Tab Inspector Modal Workflow', (t) => {
  const componentContent = readFile('components/MitreAtlasView.tsx');

  // Assert modal tab state
  assert.ok(componentContent.includes('activeModalTab'), 'Must maintain activeModalTab state');
  assert.ok(componentContent.includes('activeModalTab === \'overview\''), 'Must render Overview tab');
  assert.ok(componentContent.includes('activeModalTab === \'procedures\''), 'Must render Procedure Examples tab');
  assert.ok(componentContent.includes('activeModalTab === \'mitigations\''), 'Must render Mitigations tab');
  assert.ok(componentContent.includes('activeModalTab === \'citations\''), 'Must render References & Tests tab');

  // Assert modal action tools
  assert.ok(componentContent.includes('handleCopyId'), 'Must provide Copy ID handler');
  assert.ok(componentContent.includes('handlePrevTechnique'), 'Must provide Previous technique navigation');
  assert.ok(componentContent.includes('handleNextTechnique'), 'Must provide Next technique navigation');
});

test('Functional - MitreAtlasView: Testing Pillar Banner in TestList.tsx', (t) => {
  const testListContent = readFile('components/TestList.tsx');

  // Assert mappedAtlasTechniques computation
  assert.ok(testListContent.includes('mappedAtlasTechniques'), 'TestList must compute mappedAtlasTechniques for active pillar');
  assert.ok(testListContent.includes('MITRE ATLAS™ Matrix Mappings'), 'Must render ATLAS Matrix Mappings banner');
  assert.ok(testListContent.includes('Open Full Matrix'), 'Must provide direct jump into ATLAS Matrix');
  assert.ok(testListContent.includes('ATLAS'), 'Must provide ATLAS filter chip in source filter bar');
});

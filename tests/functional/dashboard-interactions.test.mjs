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

test('Dashboard - Interactive Components & Animations', (t) => {
  const content = readFile('components/Dashboard.tsx');

  // Verify IntersectionObserver useInView hook
  assert.ok(content.includes('function useInView'), 'Dashboard must implement useInView hook for scroll animations');
  assert.ok(content.includes('IntersectionObserver'), 'Dashboard must use IntersectionObserver for visibility tracking');

  // Verify CountUp animation
  assert.ok(content.includes('const CountUp:'), 'Dashboard must implement CountUp component');
  assert.ok(content.includes('requestAnimationFrame'), 'CountUp must use requestAnimationFrame for smooth numeric interpolation');

  // Verify Typewriter effect
  assert.ok(content.includes('const useTypewriter = (phrases: string[],'), 'Dashboard must implement useTypewriter hook');
  assert.ok(content.includes('setTimeout'), 'useTypewriter must use setTimeout for typing cadence');
});

test('Dashboard - Data Aggregations & Memoization', (t) => {
  const content = readFile('components/Dashboard.tsx');

  // Verify the 'stats' memoized aggregation block
  assert.ok(content.includes('const stats = useMemo(() => {'), 'Dashboard must memoize aggregated metrics to prevent re-renders');
  
  // Verify specific metric aggregations
  assert.ok(content.includes('byRisk: Record<TestItem[\'riskLevel\'], number>'), 'Dashboard must aggregate tests by risk level');
  assert.ok(content.includes('byPillar: Record<Pillar, TestItem[]>'), 'Dashboard must aggregate tests by Pillar');
  assert.ok(content.includes('uniqueTools.filter((t) => t.category === \'Offensive\')'), 'Dashboard must categorize tools into Offensive/Defensive');
  
  // Verify cross-framework coverage mappings
  assert.ok(content.includes('domainTests.filter((t) => t.owaspTop10Ref)'), 'Dashboard must compute LLM Top 10 coverage');
  assert.ok(content.includes('domainTests.filter((t) => t.owaspAgenticRef)'), 'Dashboard must compute Agentic Top 10 coverage');

  // Verify spotlight and sorting
  assert.ok(content.includes('stats.spotlight[spotIndex % stats.spotlight.length]'), 'Dashboard must cycle through spotlight items');
});

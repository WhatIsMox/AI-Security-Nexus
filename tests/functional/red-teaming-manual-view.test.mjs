/**
 * Functional Tests — RedTeamingManualView Component Structure & Completeness
 *
 * The OWASP GenAI Red Teaming Manual is a comprehensive 144-page framework
 * covering 8 methodology phases, 26 adversarial testing domains, refusal heuristics,
 * surface mapping & 2026 threat overlays, exfiltration channels, persistence chains,
 * empirical statistical evaluators (Confusion Matrix, Rule of Three, Wilson score),
 * and paired Red-Blue remediation artifacts.
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

// ─── 1. Data Source Imports ───────────────────────────────────────────────────

test('RedTeamingManualView - imports all primary data constants from data_red_teaming_manual', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  const expectedImports = [
    'RED_TEAMING_MANUAL_META',
    'RED_TEAMING_MANUAL_PHASES',
    'RED_TEAMING_REFUSAL_PATTERNS',
    'RED_TEAMING_TESTING_DOMAINS',
    'RED_TEAMING_SURFACE_MAP_MATRIX',
    'RED_TEAMING_INGRESS_SURFACES',
    'RED_TEAMING_SURFACE_THREAT_CROSSWALK',
    'RED_TEAMING_EXFILTRATION_CHANNELS',
    'RED_TEAMING_REAL_WORLD_CASES',
    'RED_TEAMING_PERSISTENCE_SURFACES',
    'RED_TEAMING_STANDARDIZED_TEST_CASES',
    'RED_TEAMING_STATISTICAL_METRICS',
    'RED_TEAMING_GLOSSARY',
    'RED_TEAMING_EXAMPLES',
    'RED_TEAMING_REFERENCES',
  ];

  for (const exp of expectedImports) {
    assert.ok(
      content.includes(exp),
      `RedTeamingManualView must import "${exp}"`
    );
  }
  t.diagnostic(`Verified all ${expectedImports.length} required imports in RedTeamingManualView`);
});

test('RedTeamingManualView - imports directly from data_red_teaming_manual', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  assert.ok(
    content.includes("from '../data/data_red_teaming_manual'") ||
    content.includes('from "../data/data_red_teaming_manual"'),
    'RedTeamingManualView must import directly from data_red_teaming_manual'
  );
});

// ─── 2. Tab Navigation & View Structure ──────────────────────────────────────

test('RedTeamingManualView - implements all 9 interactive tabs', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  const expectedTabs = [
    'phases',
    'domains',
    'refusal',
    'surfaces',
    'exfiltration',
    'calculator',
    'redblue',
    'cases',
    'appendix',
  ];

  for (const tab of expectedTabs) {
    assert.ok(
      content.includes(`'${tab}'`),
      `RedTeamingManualView must define tab '${tab}'`
    );
  }
  t.diagnostic(`Verified all ${expectedTabs.length} tabs in RedTeamingManualView`);
});

// ─── 3. Empirical Evaluator & Statistical Calculators ─────────────────────────

test('RedTeamingManualView - implements interactive Confusion Matrix and ASR calculation', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  // Verify confusion matrix state and formula computations
  assert.ok(content.includes('tp') && content.includes('setTp'), 'Must have True Positive state');
  assert.ok(content.includes('fp') && content.includes('setFp'), 'Must have False Positive state');
  assert.ok(content.includes('tn') && content.includes('setTn'), 'Must have True Negative state');
  assert.ok(content.includes('fn') && content.includes('setFn'), 'Must have False Negative state');

  // Formula logic presence: ASR = FN / (TP + FN)
  assert.ok(content.includes('fn / (tp + fn)'), 'Must calculate Attack Success Rate (ASR / FNR)');
  // Recall = TP / (TP + FN)
  assert.ok(content.includes('tp / (tp + fn)'), 'Must calculate Recall (TPR / 1 - ASR)');
  // FPR = FP / (FP + TN)
  assert.ok(content.includes('fp / (fp + tn)'), 'Must calculate False Positive Rate (FPR)');
  // Precision = TP / (TP + FP)
  assert.ok(content.includes('tp / (tp + fp)'), 'Must calculate Precision');
  // Accuracy = (TP + TN) / (TP + FP + TN + FN)
  assert.ok(content.includes('(tp + tn) / (tp + tn + fp + fn)'), 'Must calculate Overall Accuracy');
});

test('RedTeamingManualView - implements Rule of Three and Bounded Null Sample Sizing', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  // Rule of three formula: 3 / targetMaxAsr
  assert.ok(content.includes('3 / targetMaxAsr'), 'Must compute 3/N upper bound for zero-success trials');
  assert.ok(content.includes('calculatedSampleSizeN'), 'Must implement calculator for N from target residual ASR');
  assert.ok(content.includes('Wilson score interval') || content.includes('Wilson'), 'Must provide Wilson score interval guidance');
});

test('RedTeamingManualView - includes the 3 Adaptive Attack Diagnostic Checks', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  assert.ok(
    content.includes('Black-box exceeds white-box'),
    'Must include Diagnostic 1: Black-box vs white-box anomaly'
  );
  assert.ok(
    content.includes('Non-monotonic response to budget'),
    'Must include Diagnostic 2: Budget monotonicity check'
  );
  assert.ok(
    content.includes('Random perturbation outperforms search'),
    'Must include Diagnostic 3: Random perturbation vs targeted search'
  );
});

// ─── 4. Red-Blue Studio & Paired Deliverables ────────────────────────────────

test('RedTeamingManualView - implements Red-Blue Studio with copyable artifacts', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  assert.ok(content.includes('Red Artifact') || content.includes('Reproduction Evidence'), 'Must contain Red Artifact');
  assert.ok(content.includes('Blue Artifact') || content.includes('Detection Evidence'), 'Must contain Blue Artifact');

  // Must have clipboard copying capability
  assert.ok(content.includes('copyToClipboard'), 'Must implement copy to clipboard functionality');
  assert.ok(content.includes('navigator.clipboard.writeText'), 'Must invoke clipboard API');
});

// ─── 5. Security & CSP Conformance ───────────────────────────────────────────

test('RedTeamingManualView - adheres to strict security directives', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  // Disallow insecure methods
  assert.ok(!content.includes('dangerouslySetInnerHTML'), 'Must not use dangerouslySetInnerHTML');
  assert.ok(!content.includes('eval('), 'Must not use eval');
  assert.ok(!content.includes('new Function('), 'Must not use new Function');
  assert.ok(!content.includes('javascript:'), 'Must not use javascript: URIs');

  // Verify external links have rel="noopener noreferrer"
  const externalLinkMatches = [...content.matchAll(/<a[^>]*href=["']https?:\/\/[^"']+["'][^>]*>/g)];
  for (const match of externalLinkMatches) {
    const linkTag = match[0];
    assert.ok(
      linkTag.includes('rel="noopener noreferrer"') || linkTag.includes("rel='noopener noreferrer'"),
      `External link must specify rel="noopener noreferrer": ${linkTag}`
    );
    assert.ok(
      linkTag.includes('target="_blank"') || linkTag.includes("target='_blank'"),
      `External link must specify target="_blank": ${linkTag}`
    );
  }
});

// ─── 6. Real-World CVEs & Precedent Coverage in Data Catalog ─────────────────

test('data_red_teaming_manual - covers all required real-world CVEs and case studies', (t) => {
  const dataContent = readFile('src/data/data_red_teaming_manual.ts');

  const requiredIncidents = [
    'CVE-2025-32711', // EchoLeak
    'ShadowLeak',
    'ForcedLeak',
    'AgentFlayer',
    'CVE-2025-68664', // LangGrinch
    'CVE-2026-25592', // Semantic Kernel
    'CVE-2026-21858', // Ni8mare (n8n)
  ];

  for (const incident of requiredIncidents) {
    assert.ok(
      dataContent.includes(incident),
      `data_red_teaming_manual must contain case study/CVE "${incident}"`
    );
  }
  t.diagnostic(`Verified all ${requiredIncidents.length} CVEs/case studies in data catalog`);
});

// ─── 7. Accessibility and Responsive Design ──────────────────────────────────

test('RedTeamingManualView - implements accessible tabs and responsive layout', (t) => {
  const content = readFile('src/components/RedTeamingManualView.tsx');

  assert.ok(content.includes('role="tablist"'), 'Must define role="tablist"');
  assert.ok(content.includes('role="tab"'), 'Must define role="tab"');
  assert.ok(content.includes('aria-selected='), 'Must define aria-selected state on tabs');
  assert.ok(content.includes('content-auto'), 'Must use content-auto for large list performance containment');
});

// ─── 8. Official Resource Link Verification ──────────────────────────────────

test('RedTeamingManualView & data - links to official version 1.0 publication resource', (t) => {
  const dataContent = readFile('src/data/data_red_teaming_manual.ts');
  const viewContent = readFile('src/components/RedTeamingManualView.tsx');
  const expectedUrl = 'https://genai.owasp.org/resource/genai-red-teaming-manual-version-1-0/';

  assert.ok(
    dataContent.includes(expectedUrl),
    `data_red_teaming_manual.ts must reference "${expectedUrl}"`
  );
  assert.ok(
    viewContent.includes('RED_TEAMING_MANUAL_META.sourceDocUrl'),
    'RedTeamingManualView.tsx must render RED_TEAMING_MANUAL_META.sourceDocUrl'
  );
});

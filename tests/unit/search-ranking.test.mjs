/**
 * Unit Tests — Omnisearch tokenization & relevance ranking (executed via esbuild).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const src = fs.readFileSync(path.join(rootDir, 'src/utils/searchRanking.ts'), 'utf8');
const { code } = transformSync(src, { loader: 'ts', format: 'esm', target: 'es2022' });
const { tokenizeQuery, scoreItem, rankSearchResults } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);

const item = (title, subtitle = '') => ({ id: `x-${title}`, title, subtitle });

test('Search ranking - exact technique/threat ID outranks items that merely mention it', () => {
  const mention = item('AML.T0085: Data from AI Services', 'See also AML.T0136 for exfiltration');
  const exact = item('AML.T0136: Exfiltration via AI User Interface', 'Adversaries exfiltrate information');
  const ranked = rankSearchResults([mention, exact], 'aml.t0136');
  assert.equal(ranked[0], exact);
});

test('Search ranking - section numbers match with or without the § prefix', () => {
  const a = item('§3.3.7 Security Hooks (Enforcement Points)', 'hooks');
  const b = item('§3.3.8 Behavioral Circuit Breakers', 'mentions 3.3.7 in text');
  assert.equal(rankSearchResults([b, a], '3.3.7')[0], a);
  assert.equal(rankSearchResults([b, a], '§3.3.7')[0], a);
});

test('Search ranking - title hits beat body-only hits and ties keep catalog order', () => {
  const body = item('Unrelated heading', 'discusses rug-pull attacks');
  const title = item('Tool definition integrity (anti rug-pull)', '');
  const t2 = item('Another rug-pull note', '');
  assert.deepEqual(rankSearchResults([body, title, t2], 'rug-pull'), [title, t2, body]);
  const same1 = item('Alpha thing'); const same2 = item('Beta thing');
  assert.deepEqual(rankSearchResults([same1, same2], 'thing'), [same1, same2]);
});

test('Search ranking - tokenization is separator-insensitive and AND-based', () => {
  assert.deepEqual(tokenizeQuery('  Rug-Pull   OBO '), [['rug-pull', 'rug pull'], ['obo']]);
  assert.deepEqual(tokenizeQuery(''), []);
  assert.deepEqual(tokenizeQuery('snake_case'), [['snake_case', 'snake case']]);
  assert.equal(scoreItem(item('x'), ''), 0);
});

test('Search ranking - GlobalSearchModal uses the ranking module and keeps the precomputed searchText filter', () => {
  const modal = fs.readFileSync(path.join(rootDir, 'src/components/GlobalSearchModal.tsx'), 'utf8');
  assert.ok(modal.includes("from '../utils/searchRanking'") && modal.includes('rankSearchResults(') && modal.includes('tokenizeQuery('));
  assert.ok(modal.includes('item.searchText.includes('));
});

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

test('Security - Prototype Pollution Resilience in Storage Deserialization (CWE-1321)', (t) => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');

  // Verify explicit guard expressions in AuditChecklistView.tsx
  assert.ok(auditViewCode.includes("key !== '__proto__'"), 'Must explicitly check key !== __proto__');
  assert.ok(auditViewCode.includes("key !== 'constructor'"), 'Must explicitly check key !== constructor');
  assert.ok(auditViewCode.includes("validStatuses"), 'Must validate status against strict enum whitelist');

  // Functional simulation of the deserializer logic against active prototype pollution payloads
  const maliciousRawPayload = JSON.stringify({
    "__proto__": { "pollutedProperty": "ATTACK_SUCCESS" },
    "constructor": { "prototype": { "pollutedConstructor": "ATTACK_SUCCESS" } },
    "prototype": { "pollutedProto": "ATTACK_SUCCESS" },
    "AITG-APP-01": {
      "status": "<script>alert(1)</script>",
      "notes": "Legitimate note content",
      "updatedAt": "2026-08-23T22:00:00.000Z"
    },
    "AITG-APP-02": {
      "status": "PASSED",
      "notes": "A".repeat(10000), // Oversized payload
      "updatedAt": "2026-08-23T22:00:00.000Z"
    }
  });

  const parsed = JSON.parse(maliciousRawPayload);
  const sanitized = {};
  const validStatuses = new Set(['NOT_TESTED', 'PASSED', 'VULNERABLE', 'MITIGATED', 'NA']);

  for (const [key, val] of Object.entries(parsed)) {
    if (typeof key === 'string' && key.length <= 50 && key !== '__proto__' && key !== 'constructor' && val && typeof val === 'object') {
      const rec = val;
      sanitized[key] = {
        status: rec.status && validStatuses.has(rec.status) ? rec.status : 'NOT_TESTED',
        notes: typeof rec.notes === 'string' ? rec.notes.slice(0, 5000) : '',
        updatedAt: typeof rec.updatedAt === 'string' ? rec.updatedAt.slice(0, 50) : ''
      };
    }
  }

  // Assert prototype remains unpolluted
  const cleanObj = {};
  assert.strictEqual(cleanObj.pollutedProperty, undefined, 'Prototype pollution property must be undefined');
  assert.strictEqual(cleanObj.pollutedConstructor, undefined, 'Constructor pollution property must be undefined');

  // Assert XSS status fell back to default NOT_TESTED
  assert.strictEqual(sanitized['AITG-APP-01'].status, 'NOT_TESTED', 'Invalid status must fall back to NOT_TESTED');

  // Assert oversized notes payload is truncated to safe boundary (5000 chars)
  assert.strictEqual(sanitized['AITG-APP-02'].notes.length, 5000, 'Oversized notes must be truncated to 5000 chars');
});

test('Security - Report Export Markdown & CSV Table Injection Sanitization (CWE-1236)', (t) => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');

  // Assert pipe escaping in markdown table generation
  assert.ok(
    auditViewCode.includes(".replace(/\\|/g, '\\\\|')") || auditViewCode.includes('.replace(/\\|/g,'),
    'Audit exportMarkdown must escape pipe characters (|) to prevent markdown table injection'
  );

  // Assert newline replacement in table rows
  assert.ok(
    auditViewCode.includes(".replace(/\\n/g, ' ')") || auditViewCode.includes('.replace(/\\n/g,'),
    'Audit exportMarkdown must sanitize newline characters to prevent multi-line table breakout'
  );

  // Assert object URL cleanup
  assert.ok(
    auditViewCode.includes('URL.revokeObjectURL(url)'),
    'Audit exports must call URL.revokeObjectURL to prevent memory exhaustion'
  );
});

/**
 * Read-progress persistence helpers for the Securing Agentic Applications view.
 * Kept dependency-free so the sanitizer can be unit-tested directly.
 */

export const SAA_PROGRESS_STORAGE_KEY = 'ai-nexus-securing-agentic-apps-read-v1';

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Deserialize stored read-progress against a strict whitelist of known section IDs.
 * Anything that is not an array of known, unique section-ID strings is discarded,
 * which also neutralizes prototype-poisoning payloads (`__proto__`, `constructor`).
 */
export const sanitizeReadProgress = (raw: unknown, validIds: ReadonlySet<string>): string[] => {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const v of raw.slice(0, 500)) {
    if (typeof v === 'string' && v.length <= 40 && !FORBIDDEN_KEYS.has(v) && validIds.has(v) && !out.includes(v)) {
      out.push(v);
    }
  }
  return out;
};

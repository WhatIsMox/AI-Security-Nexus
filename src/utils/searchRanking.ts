/**
 * Omnisearch helpers: tokenization with separator-insensitive variants and relevance ranking.
 * Pure and dependency-free so it can be unit-tested directly.
 */

export interface RankableItem {
  id: string;
  title: string;
  subtitle: string;
}

/**
 * Splits a lower-cased query into whitespace-separated tokens. Each token yields the spellings
 * that should be treated as equivalent ("rug-pull" / "rug pull" / "rug_pull").
 */
export const tokenizeQuery = (query: string): string[][] =>
  query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((token) => {
      const variants = new Set<string>([token]);
      if (/[-_]/.test(token)) variants.add(token.replace(/[-_]+/g, ' '));
      return [...variants];
    });

/** Relevance score: exact ID / title-prefix matches first, then title hits, then body-only hits. */
export const scoreItem = (item: RankableItem, query: string): number => {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const title = item.title.toLowerCase();
  let score = 1;
  const idToken = title.replace(/^§/, '').split(/[:\s]/)[0];
  if (idToken === q.replace(/^§/, '')) score += 200;
  else if (title.startsWith(q) || title.replace(/^§/, '').startsWith(q)) score += 120;
  else if (title.includes(q)) score += 60;
  const tokens = q.split(/\s+/).filter(Boolean);
  if (tokens.length > 1 && tokens.every((t) => title.includes(t))) score += 30;
  for (const t of tokens) if (title.includes(t)) score += 5;
  if (item.subtitle.toLowerCase().includes(q)) score += 10;
  return score;
};

/** Stable sort by descending relevance (ties keep catalog order). */
export const rankSearchResults = <T extends RankableItem>(items: readonly T[], query: string): T[] =>
  items
    .map((item, index) => ({ item, index, score: scoreItem(item, query) }))
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((x) => x.item);

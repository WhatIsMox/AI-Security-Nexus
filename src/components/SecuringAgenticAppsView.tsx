import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck, Search, ExternalLink, ChevronDown, ChevronRight, CheckCircle2, Circle, Link2, Check,
  BookOpen, Sparkles, Info, AlertTriangle, KeyRound, X, ListTree, RotateCcw, ArrowRight, FileText, Target, Bot, Network,
} from 'lucide-react';
import {
  SECURING_AGENTIC_APPS_META,
  SAA_CHAPTERS,
  SAA_ALL_SECTIONS,
  SAA_SECTION_SEARCH_TEXT,
  SAA_THREATS,
  SAA_KEY_COMPONENTS,
  SAA_HOOKS,
  SAA_EDITORIAL_NOTES,
  SaaBlock,
  SaaListItem,
  SaaSection,
  SaaWidgetId,
} from '../data/data_securing_agentic_apps';
import { SaaWidget, SAA_WIDGET_LABELS } from './securing-agentic/SaaWidgets';
import { SAA_PROGRESS_STORAGE_KEY, sanitizeReadProgress } from './securing-agentic/readProgress';

const VALID_SECTION_IDS: ReadonlySet<string> = new Set(SAA_ALL_SECTIONS.map((s) => s.id));

interface SecuringAgenticAppsViewProps {
  initialSectionId?: string | null;
  onNavigateToOwasp?: (id: string) => void;
  onSelectPillar?: (pillar: 'SECUREMCPGUIDE' | 'REDTEAMINGMANUAL' | 'AGENTTOP10' | 'MCPTOP10') => void;
}

// ─── Text helpers ────────────────────────────────────────────────────────────

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const Highlight: React.FC<{ text: string; query: string }> = ({ text, query }) => {
  const q = query.trim();
  if (q.length < 2) return <>{text}</>;
  const parts = text.split(new RegExp(`(${escapeRegExp(q)})`, 'ig'));
  return (
    <>
      {parts.map((part, i) =>
        part.toLowerCase() === q.toLowerCase() ? <mark key={i} className="bg-violet-500/30 text-violet-100 rounded px-0.5">{part}</mark> : <React.Fragment key={i}>{part}</React.Fragment>,
      )}
    </>
  );
};

const ListItems: React.FC<{ items: SaaListItem[]; ordered?: boolean; query: string; depth?: number }> = ({ items, ordered, query, depth = 0 }) => {
  const Tag = ordered ? 'ol' : 'ul';
  return (
    <Tag className={`space-y-2 ${depth > 0 ? 'mt-2 pl-4 border-l border-slate-800' : ''}`}>
      {items.map((it, i) => (
        <li key={i} className="flex gap-2.5 text-sm text-slate-300 leading-relaxed">
          <span className={`shrink-0 mt-[3px] ${ordered ? 'w-5 h-5 rounded-full bg-violet-500/15 border border-violet-500/40 text-violet-200 text-[10px] font-mono flex items-center justify-center' : 'w-1.5 h-1.5 mt-[9px] rounded-full bg-violet-400/70'}`}>
            {ordered ? i + 1 : null}
          </span>
          <div className="min-w-0">
            {it.label && <span className="font-semibold text-slate-100"><Highlight text={it.label} query={query} />{it.text ? ' — ' : ''}</span>}
            {it.text && <Highlight text={it.text} query={query} />}
            {it.children && <ListItems items={it.children} query={query} depth={depth + 1} />}
          </div>
        </li>
      ))}
    </Tag>
  );
};

interface BlockProps {
  block: SaaBlock;
  query: string;
  focusThreat: string | null;
  onNavigateToOwasp?: (id: string) => void;
  onJumpToSection: (id: string) => void;
}

const Block: React.FC<BlockProps> = ({ block, query, focusThreat, onNavigateToOwasp, onJumpToSection }) => {
  switch (block.type) {
    case 'p':
      return <p className="text-sm text-slate-300 leading-relaxed"><Highlight text={block.text} query={query} /></p>;
    case 'list':
      return <ListItems items={block.items} ordered={block.ordered} query={query} />;
    case 'callout': {
      const tone = {
        info: { box: 'border-sky-500/30 bg-sky-500/5', icon: <Info className="w-4 h-4 text-sky-300 shrink-0 mt-0.5" />, title: 'text-sky-200' },
        warning: { box: 'border-amber-500/30 bg-amber-500/5', icon: <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />, title: 'text-amber-200' },
        key: { box: 'border-violet-500/40 bg-violet-500/10', icon: <KeyRound className="w-4 h-4 text-violet-300 shrink-0 mt-0.5" />, title: 'text-violet-200' },
      }[block.tone];
      return (
        <div className={`rounded-xl border p-3.5 flex gap-3 ${tone.box}`}>
          {tone.icon}
          <div className="text-sm text-slate-300 leading-relaxed min-w-0">
            {block.title && <div className={`text-xs font-bold uppercase tracking-wide mb-1 ${tone.title}`}>{block.title}</div>}
            <Highlight text={block.text} query={query} />
          </div>
        </div>
      );
    }
    case 'table':
      return (
        <div className="space-y-1.5">
          {block.caption && <div className="text-xs font-semibold text-slate-400">{block.caption}</div>}
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full min-w-[560px] text-xs">
              <thead className="bg-slate-900/80">
                <tr>{block.headers.map((h) => <th key={h} scope="col" className="text-left px-3 py-2 font-semibold text-slate-200 border-b border-slate-800">{h}</th>)}</tr>
              </thead>
              <tbody>
                {block.rows.map((r, ri) => (
                  <tr key={ri} className="odd:bg-slate-950/40 even:bg-slate-900/30 align-top">
                    {r.map((c, ci) => (
                      <td key={ci} className={`px-3 py-2 leading-relaxed border-b border-slate-800/60 ${ci === 0 ? 'text-slate-100 font-medium' : 'text-slate-300'}`}>
                        {/^https?:\/\//.test(c) ? (
                          <a href={c} target="_blank" rel="noopener noreferrer" className="text-violet-300 hover:text-violet-100 break-all inline-flex items-center gap-1">{c.replace(/^https?:\/\//, '')}<ExternalLink className="w-3 h-3 shrink-0" /></a>
                        ) : <Highlight text={c} query={query} />}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );
    case 'formula':
      return (
        <div className="rounded-xl border border-violet-500/40 bg-gradient-to-r from-violet-500/10 to-fuchsia-500/5 p-4 text-center">
          <div className="font-mono text-sm sm:text-base text-violet-100 break-words">{block.text}</div>
          {block.caption && <div className="text-xs text-slate-400 mt-1">{block.caption}</div>}
        </div>
      );
    case 'links':
      return (
        <div className="flex flex-wrap gap-2">
          {block.items.map((l) => (
            <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs bg-slate-900 border border-slate-700 text-violet-300 hover:border-violet-500/60 hover:text-violet-100 transition-colors">
              {l.label}<ExternalLink className="w-3 h-3" />
            </a>
          ))}
        </div>
      );
    case 'widget':
      return (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-fuchsia-300"><Sparkles className="w-3.5 h-3.5" />Interactive · {SAA_WIDGET_LABELS[block.widget]}</div>
          <SaaWidget id={block.widget} onNavigateToOwasp={onNavigateToOwasp} onJumpToSection={onJumpToSection} focusThreat={focusThreat} />
        </div>
      );
  }
};

// ─── Widget → section map (for the "Interactive labs" strip) ────────────────

const WIDGET_SECTIONS: { widget: SaaWidgetId; sectionId: string }[] = SAA_ALL_SECTIONS.flatMap((s) =>
  s.blocks.filter((b): b is Extract<SaaBlock, { type: 'widget' }> => b.type === 'widget').map((b) => ({ widget: b.widget, sectionId: s.id })),
);

// ─── View ───────────────────────────────────────────────────────────────────

export const SecuringAgenticAppsView: React.FC<SecuringAgenticAppsViewProps> = ({ initialSectionId, onNavigateToOwasp, onSelectPillar }) => {
  const meta = SECURING_AGENTIC_APPS_META;

  const resolveInitial = () => {
    if (initialSectionId) {
      const ch = SAA_CHAPTERS.find((c) => c.id.toLowerCase() === initialSectionId.toLowerCase());
      if (ch) return { chapter: ch.id, section: ch.sections[0]?.id ?? null };
      const s = SAA_ALL_SECTIONS.find((x) => x.id.toLowerCase() === initialSectionId.toLowerCase());
      if (s) return { chapter: s.chapterId, section: s.id };
    }
    return { chapter: SAA_CHAPTERS[0].id, section: SAA_CHAPTERS[0].sections[0]?.id ?? null };
  };
  const initial = useMemo(resolveInitial, []); // eslint-disable-line react-hooks/exhaustive-deps

  const [chapterId, setChapterId] = useState(initial.chapter);
  const [expanded, setExpanded] = useState<Record<string, boolean>>(initial.section ? { [initial.section]: true } : {});
  const [query, setQuery] = useState('');
  const [focusThreat, setFocusThreat] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [pendingScroll, setPendingScroll] = useState<string | null>(initialSectionId ? initial.section : null);
  const [readIds, setReadIds] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem(SAA_PROGRESS_STORAGE_KEY);
      return saved ? sanitizeReadProgress(JSON.parse(saved), VALID_SECTION_IDS) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(SAA_PROGRESS_STORAGE_KEY, JSON.stringify(readIds));
    } catch {
      // storage unavailable (private mode / quota) — progress stays in memory
    }
  }, [readIds]);

  useEffect(() => {
    if (!pendingScroll) return;
    const handle = window.setTimeout(() => {
      document.getElementById(`saa-section-${pendingScroll}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setPendingScroll(null);
    }, 80);
    return () => window.clearTimeout(handle);
  }, [pendingScroll, chapterId]);

  const chapter = SAA_CHAPTERS.find((c) => c.id === chapterId) ?? SAA_CHAPTERS[0];
  const chapterIndex = SAA_CHAPTERS.findIndex((c) => c.id === chapter.id);

  const openSection = useCallback((sectionId: string) => {
    const s = SAA_ALL_SECTIONS.find((x) => x.id === sectionId);
    if (!s) return;
    setQuery('');
    setChapterId(s.chapterId);
    setExpanded((e) => ({ ...e, [s.id]: true }));
    setPendingScroll(s.id);
  }, []);

  const selectChapter = (id: string) => {
    const ch = SAA_CHAPTERS.find((c) => c.id === id);
    setChapterId(id);
    setQuery('');
    if (ch?.sections[0]) setExpanded((e) => ({ ...e, [ch.sections[0].id]: true }));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const toggleRead = (id: string) => setReadIds((r) => (r.includes(id) ? r.filter((x) => x !== id) : [...r, id]));

  const copyLink = (id: string) => {
    const url = `${window.location.origin}${window.location.pathname}#/securing-agentic-apps/${id}`;
    try {
      void navigator.clipboard.writeText(url).then(() => {
        setCopied(id);
        window.setTimeout(() => setCopied(null), 1800);
      });
    } catch {
      // clipboard unavailable
    }
  };

  const onThreatClick = (t: string) => {
    setFocusThreat(t);
    openSection('SAA-2.2');
  };

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 2) return [];
    const tokens = q.split(/\s+/).filter(Boolean);
    return SAA_ALL_SECTIONS.filter((s) => tokens.every((t) => SAA_SECTION_SEARCH_TEXT[s.id]?.includes(t)));
  }, [query]);

  const totalSections = SAA_ALL_SECTIONS.length;
  const readPct = Math.round((readIds.length / totalSections) * 100);
  const chapterRead = (chId: string) => {
    const ch = SAA_CHAPTERS.find((c) => c.id === chId);
    if (!ch) return 0;
    return ch.sections.filter((s) => readIds.includes(s.id)).length;
  };

  const allExpanded = chapter.sections.every((s) => expanded[s.id]);
  const setAll = (open: boolean) => setExpanded((e) => ({ ...e, ...Object.fromEntries(chapter.sections.map((s) => [s.id, open])) }));

  const renderSection = (s: SaaSection) => {
    const isOpen = !!expanded[s.id];
    const isRead = readIds.includes(s.id);
    return (
      <article key={s.id} id={`saa-section-${s.id}`} className="content-auto scroll-mt-24 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md transition-all duration-200 hover:border-violet-500/30">
        <div className="flex items-start gap-2 p-4 sm:p-5">
          <button
            type="button"
            aria-expanded={isOpen}
            aria-controls={`saa-body-${s.id}`}
            onClick={() => setExpanded((e) => ({ ...e, [s.id]: !isOpen }))}
            className="flex-1 min-w-0 text-left flex items-start gap-3"
          >
            {isOpen ? <ChevronDown className="w-4 h-4 text-violet-300 mt-1 shrink-0" /> : <ChevronRight className="w-4 h-4 text-slate-500 mt-1 shrink-0" />}
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold text-violet-300">§{s.number}</span>
                <h3 className="text-base font-bold text-slate-100 leading-snug"><Highlight text={s.title} query={query} /></h3>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-1 leading-relaxed"><Highlight text={s.summary} query={query} /></p>
            </div>
          </button>
          <div className="flex items-center gap-1 shrink-0">
            <button type="button" onClick={() => copyLink(s.id)} className="p-2 rounded-lg text-slate-500 hover:text-violet-200 hover:bg-slate-800 transition-colors" aria-label={`Copy link to section ${s.number}`} title="Copy deep link">
              {copied === s.id ? <Check className="w-4 h-4 text-emerald-400" /> : <Link2 className="w-4 h-4" />}
            </button>
            <button type="button" onClick={() => toggleRead(s.id)} aria-pressed={isRead} className="p-2 rounded-lg hover:bg-slate-800 transition-colors" aria-label={isRead ? `Mark section ${s.number} as unread` : `Mark section ${s.number} as read`} title={isRead ? 'Read' : 'Mark as read'}>
              {isRead ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Circle className="w-4 h-4 text-slate-600" />}
            </button>
          </div>
        </div>
        {s.threats && s.threats.length > 0 && (
          <div className="px-4 sm:px-5 -mt-2 pb-3 flex flex-wrap gap-1.5 pl-11 sm:pl-12">
            {s.threats.map((t) => (
              <button key={t} type="button" onClick={() => onThreatClick(t)} title={SAA_THREATS.find((x) => x.id === t)?.name} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/10 text-rose-300 border border-rose-500/25 hover:border-rose-400/60 transition-colors">{t}</button>
            ))}
          </div>
        )}
        {isOpen && (
          <div id={`saa-body-${s.id}`} className="px-4 sm:px-5 pb-5 pt-1 space-y-4 border-t border-slate-800/70">
            <div className="h-1" />
            {s.blocks.map((b, i) => (
              <Block key={i} block={b} query={query} focusThreat={focusThreat} onNavigateToOwasp={onNavigateToOwasp} onJumpToSection={openSection} />
            ))}
            {!isRead && (
              <button type="button" onClick={() => toggleRead(s.id)} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors">
                <CheckCircle2 className="w-3.5 h-3.5" /> Mark as read
              </button>
            )}
          </div>
        )}
      </article>
    );
  };

  // Group sections by their `group` label for the chapter body and TOC
  const grouped = useMemo(() => {
    const out: { group: string | null; sections: SaaSection[] }[] = [];
    for (const s of chapter.sections) {
      const g = s.group ?? null;
      const last = out[out.length - 1];
      if (last && last.group === g) last.sections.push(s);
      else out.push({ group: g, sections: [s] });
    }
    return out;
  }, [chapter]);

  const stats = [
    { label: 'Chapters', value: '9', tone: 'text-violet-300' },
    { label: 'Sections', value: String(totalSections), tone: 'text-fuchsia-300' },
    { label: 'Key components', value: String(SAA_KEY_COMPONENTS.length), tone: 'text-sky-300' },
    { label: 'Threats (T-codes)', value: String(SAA_THREATS.length), tone: 'text-rose-300' },
    { label: 'Hook points', value: String(SAA_HOOKS.length), tone: 'text-amber-300' },
    { label: 'Interactive labs', value: String(WIDGET_SECTIONS.length), tone: 'text-emerald-300' },
  ];

  return (
    <div className="container-fluid px-3 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6 animate-fade-in pb-16">
      {/* ─── Hero ─────────────────────────────────────────────── */}
      <header className="relative overflow-hidden rounded-2xl border border-violet-500/30 bg-gradient-to-br from-slate-950 via-slate-900 to-violet-950/30 p-5 sm:p-8 shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl pointer-events-none -mr-24 -mt-24" />
        <div className="absolute bottom-0 left-1/4 w-72 h-72 bg-fuchsia-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-violet-500/10 text-violet-300 border border-violet-500/30">
              <ShieldCheck className="w-3.5 h-3.5" /> {meta.project} · {meta.initiative}
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">Version {meta.version} • {meta.publicationDate}</span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">CC BY-SA 4.0</span>
            <a href={meta.sourceUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono bg-violet-500/20 text-violet-200 border border-violet-500/40 hover:bg-violet-500/30 hover:text-white transition-all">
              Official OWASP publication <ExternalLink className="w-3 h-3" />
            </a>
          </div>
          <div className="space-y-2">
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight">
              <span className="bg-gradient-to-r from-violet-300 via-fuchsia-300 to-cyan-300 bg-clip-text text-transparent">{meta.title}</span>
            </h1>
            <p className="text-sm sm:text-base text-slate-300 max-w-4xl leading-relaxed">
              {meta.subtitle}. The practical "how" companion to the ASI Threats &amp; Mitigations: secure architectures, developer lifecycle controls, enforcement hooks, circuit breakers, capability composition, supply-chain integrity, assurance, and runtime hardening for agentic AI.
            </p>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pt-3 border-t border-slate-800/80">
            {stats.map((s) => (
              <div key={s.label} className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono uppercase text-slate-500 font-semibold">{s.label}</div>
                <div className={`text-lg font-bold ${s.tone}`}>{s.value}</div>
              </div>
            ))}
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span className="flex items-center gap-1.5"><BookOpen className="w-3.5 h-3.5" /> Reading progress — {readIds.length}/{totalSections} sections ({readPct}%)</span>
              {readIds.length > 0 && (
                <button type="button" onClick={() => setReadIds([])} className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-300"><RotateCcw className="w-3 h-3" />Reset</button>
              )}
            </div>
            <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden" role="progressbar" aria-valuenow={readPct} aria-valuemin={0} aria-valuemax={100} aria-label="Reading progress">
              <div className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-400 transition-all duration-500" style={{ width: `${readPct}%` }} />
            </div>
          </div>
        </div>
      </header>

      {/* ─── Interactive labs + related frameworks ─────────────── */}
      <section aria-label="Interactive labs" className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4 space-y-3">
        <div className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase tracking-wider text-fuchsia-300"><Sparkles className="w-3.5 h-3.5" />Jump to an interactive lab</div>
        <div className="flex flex-wrap gap-1.5">
          {WIDGET_SECTIONS.map((w) => (
            <button key={w.widget} type="button" onClick={() => openSection(w.sectionId)} className="px-2.5 py-1 rounded-lg text-xs bg-slate-950/70 border border-slate-800 text-slate-300 hover:border-fuchsia-500/50 hover:text-fuchsia-100 transition-all duration-200">
              {SAA_WIDGET_LABELS[w.widget]}
            </button>
          ))}
        </div>
        {(onNavigateToOwasp || onSelectPillar) && (
          <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-800">
            <span className="text-[11px] text-slate-500 mr-1">Related in this app:</span>
            {onNavigateToOwasp && (
              <button type="button" onClick={() => onNavigateToOwasp('ASI01')} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400/70"><Bot className="w-3.5 h-3.5" />Agentic Top 10 (ASI)</button>
            )}
            {onSelectPillar && (
              <>
                <button type="button" onClick={() => onSelectPillar('MCPTOP10')} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400/70"><Network className="w-3.5 h-3.5" />MCP Top 10</button>
                <button type="button" onClick={() => onSelectPillar('SECUREMCPGUIDE')} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 hover:border-indigo-400/70"><FileText className="w-3.5 h-3.5" />Secure MCP Server Guide</button>
                <button type="button" onClick={() => onSelectPillar('REDTEAMINGMANUAL')} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:border-rose-400/70"><Target className="w-3.5 h-3.5" />GenAI Red Teaming Manual</button>
              </>
            )}
          </div>
        )}
      </section>

      {/* ─── Chapter tabs + search ─────────────────────────────── */}
      <div className="sticky top-16 md:top-0 z-20 -mx-3 sm:mx-0 px-3 sm:px-0 py-2 bg-slate-950/90 backdrop-blur-md space-y-2">
        <div className="flex flex-col lg:flex-row lg:items-center gap-2">
          <div role="tablist" aria-label="Guide chapters" className="flex gap-1.5 overflow-x-auto pb-1 lg:pb-0 flex-1 min-w-0 scrollbar-thin">
            {SAA_CHAPTERS.map((c) => {
              const active = c.id === chapter.id && !query;
              const done = chapterRead(c.id);
              return (
                <button
                  key={c.id}
                  type="button"
                  role="tab"
                  id={`saa-tab-${c.id}`}
                  aria-selected={active}
                  aria-controls="saa-chapter-panel"
                  onClick={() => selectChapter(c.id)}
                  className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all duration-200 ${
                    active ? 'bg-violet-500 text-white border-violet-400 shadow-md shadow-violet-500/20' : 'bg-slate-900/90 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-violet-500/40'
                  }`}
                >
                  <span className="font-mono opacity-80">{c.number}</span>
                  <span className="whitespace-nowrap">{c.shortTitle}</span>
                  {done > 0 && <span className={`text-[9px] font-mono px-1 rounded ${active ? 'bg-white/20' : 'bg-emerald-500/15 text-emerald-300'}`}>{done}/{c.sections.length}</span>}
                </button>
              );
            })}
          </div>
          <div className="relative w-full lg:w-72 shrink-0">
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search the guide (e.g. rug-pull, OBO, hooks)…"
              aria-label="Search Securing Agentic Applications guide"
              className="w-full bg-slate-900/90 border border-slate-800 focus:border-violet-500/60 rounded-xl pl-9 pr-8 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-violet-500/30 transition-all"
            />
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            {query && (
              <button type="button" onClick={() => setQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300" aria-label="Clear search"><X className="w-3.5 h-3.5" /></button>
            )}
          </div>
        </div>
      </div>

      {/* ─── Search results ────────────────────────────────────── */}
      {query.trim().length >= 2 ? (
        <section aria-label="Search results" className="space-y-3">
          <div className="text-xs text-slate-400">{results.length} section{results.length === 1 ? '' : 's'} match “{query.trim()}”</div>
          {results.length === 0 && <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center text-sm text-slate-400">No sections match. Try a broader term such as “memory”, “token”, or “sandbox”.</div>}
          {results.map((s) => (
            <button key={s.id} type="button" onClick={() => openSection(s.id)} className="content-auto w-full text-left rounded-xl border border-slate-800 bg-slate-900/40 p-4 hover:border-violet-500/50 transition-all duration-200 group">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-violet-500/15 text-violet-300 border border-violet-500/30">Ch. {s.chapterNumber} · {s.chapterTitle}</span>
                <span className="font-mono text-xs text-violet-300">§{s.number}</span>
                <span className="text-sm font-semibold text-slate-100"><Highlight text={s.title} query={query} /></span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed"><Highlight text={s.summary} query={query} /></p>
              <span className="text-[11px] text-violet-300 inline-flex items-center gap-1 mt-1.5 opacity-70 group-hover:opacity-100">Open section <ArrowRight className="w-3 h-3" /></span>
            </button>
          ))}
        </section>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr] gap-6 items-start">
          {/* ─── TOC ─────────────────────────────────────────────── */}
          <nav aria-label={`Sections in chapter ${chapter.number}`} className="hidden lg:block sticky top-20 max-h-[calc(100vh-6rem)] overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900/40 p-3 space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 flex items-center gap-1.5 px-1"><ListTree className="w-3.5 h-3.5" />Chapter {chapter.number}</div>
            {grouped.map((g, gi) => (
              <div key={gi} className="space-y-0.5">
                {g.group && <div className="text-[10px] font-semibold text-slate-500 px-1 pt-1.5">{g.group}</div>}
                {g.sections.map((s) => (
                  <button key={s.id} type="button" onClick={() => openSection(s.id)} className={`w-full text-left flex items-start gap-1.5 px-2 py-1 rounded-md text-xs transition-colors ${expanded[s.id] ? 'text-violet-200 bg-violet-500/10' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'}`}>
                    {readIds.includes(s.id) ? <CheckCircle2 className="w-3 h-3 mt-0.5 shrink-0 text-emerald-400" /> : <span className="w-3 shrink-0" />}
                    <span className="font-mono text-[10px] mt-px shrink-0 opacity-70">{s.number.length <= 6 ? s.number : ''}</span>
                    <span className="leading-snug">{s.title}</span>
                  </button>
                ))}
              </div>
            ))}
          </nav>

          {/* ─── Chapter body ────────────────────────────────────── */}
          <section id="saa-chapter-panel" role="tabpanel" aria-labelledby={`saa-tab-${chapter.id}`} className="space-y-4 min-w-0">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <div className="text-xs font-mono text-violet-300">Chapter {chapter.number} of {SAA_CHAPTERS.length - 1}{chapter.number === 'A' ? ' · appendix' : ''}</div>
                <h2 className="text-xl sm:text-2xl font-bold text-slate-100">{chapter.title}</h2>
                <p className="text-sm text-slate-400 mt-1 max-w-3xl">{chapter.tagline}</p>
              </div>
              <button type="button" onClick={() => setAll(!allExpanded)} className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:border-violet-500/50">
                {allExpanded ? 'Collapse all' : 'Expand all'}
              </button>
            </div>

            {grouped.map((g, gi) => (
              <div key={gi} className="space-y-3">
                {g.group && <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-500 pt-2">{g.group}</h3>}
                {g.sections.map(renderSection)}
              </div>
            ))}

            {chapter.id === 'SAA-ACK' && (
              <details className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
                <summary className="cursor-pointer text-sm font-semibold text-slate-200">Editorial notes — corrections applied to the source ({SAA_EDITORIAL_NOTES.length})</summary>
                <ul className="mt-3 space-y-1.5">
                  {SAA_EDITORIAL_NOTES.map((n) => <li key={n} className="text-xs text-slate-400 leading-relaxed pl-3 border-l-2 border-violet-500/30">{n}</li>)}
                </ul>
              </details>
            )}

            <div className="flex items-center justify-between gap-2 pt-2">
              {chapterIndex > 0 ? (
                <button type="button" onClick={() => selectChapter(SAA_CHAPTERS[chapterIndex - 1].id)} className="px-3 py-2 rounded-xl text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:border-violet-500/50">← {SAA_CHAPTERS[chapterIndex - 1].shortTitle}</button>
              ) : <span />}
              {chapterIndex < SAA_CHAPTERS.length - 1 && (
                <button type="button" onClick={() => selectChapter(SAA_CHAPTERS[chapterIndex + 1].id)} className="px-3 py-2 rounded-xl text-xs bg-violet-500/15 border border-violet-500/40 text-violet-200 hover:bg-violet-500/25">{SAA_CHAPTERS[chapterIndex + 1].shortTitle} →</button>
              )}
            </div>
          </section>
        </div>
      )}

      <footer className="text-[11px] text-slate-500 leading-relaxed border-t border-slate-800 pt-4">
        Adapted from <a href={meta.sourceUrl} target="_blank" rel="noopener noreferrer" className="text-violet-300 hover:text-violet-100">{meta.title} ({meta.subtitle}, v{meta.version}, {meta.publicationDate})</a> by the {meta.project}, licensed under <a href={meta.license.url} target="_blank" rel="noopener noreferrer" className="text-violet-300 hover:text-violet-100">CC BY-SA 4.0</a>. Changes: restructured into interactive sections, lightly edited, cross-references corrected. {meta.disclaimer}
      </footer>
    </div>
  );
};

export default SecuringAgenticAppsView;

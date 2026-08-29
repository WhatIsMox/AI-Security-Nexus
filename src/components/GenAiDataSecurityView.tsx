import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  Database,
  ExternalLink,
  FileText,
  Filter,
  Layers,
  ListChecks,
  Search,
  ShieldCheck,
  Sparkles,
  Target,
  X,
} from 'lucide-react';
import {
  GENAI_DATA_SECURITY_META,
  GENAI_DATA_SECURITY_OVERVIEW,
  GENAI_DATA_SECURITY_RISKS,
  GENAI_DSPM_CAPABILITIES,
  GenAiDataSecurityRisk,
  GenAiDataSecurityTier,
} from '../data/data_genai_data_security';

type ThemeFilter = GenAiDataSecurityRisk['theme'] | 'All';

const THEME_STYLES: Record<GenAiDataSecurityRisk['theme'], { label: string; badge: string; border: string; dot: string }> = {
  'Leakage & Exposure': {
    label: 'Leakage',
    badge: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
    border: 'border-rose-500/20',
    dot: 'bg-rose-400'
  },
  'Identity, Tools & Agents': {
    label: 'Identity',
    badge: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
    border: 'border-cyan-500/20',
    dot: 'bg-cyan-400'
  },
  'Governance & Compliance': {
    label: 'Governance',
    badge: 'border-blue-500/30 bg-blue-500/10 text-blue-200',
    border: 'border-blue-500/20',
    dot: 'bg-blue-400'
  },
  'Integrity & Resilience': {
    label: 'Integrity',
    badge: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
    border: 'border-amber-500/20',
    dot: 'bg-amber-400'
  },
  'Model, Vector & Inference': {
    label: 'Model/Vector',
    badge: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    border: 'border-emerald-500/20',
    dot: 'bg-emerald-400'
  }
};

const includesSearch = (risk: GenAiDataSecurityRisk, search: string) => {
  const term = search.trim().toLowerCase();
  if (!term) return true;
  const haystack = [
    risk.id,
    risk.title,
    risk.theme,
    risk.summary,
    ...risk.keywords,
    ...risk.howItUnfolds,
    ...risk.attackerCapabilities,
    risk.illustrativeScenario,
    ...risk.impacts,
    ...(risk.knownExploits || []),
    ...(risk.crossReferences || []),
    ...risk.mitigations.flatMap((group) => [
      group.label,
      group.intent,
      ...group.items.flatMap((item) => [item.title, item.description, item.scope || ''])
    ])
  ].join(' ').toLowerCase();
  return haystack.includes(term);
};

const HighlightedBullet: React.FC<{ item: string; accent?: 'cyan' | 'emerald' }> = ({ item, accent = 'cyan' }) => {
  const [label, ...rest] = item.split(':');
  const description = rest.join(':').trim();
  const color = accent === 'cyan'
    ? 'border-cyan-500/25 bg-cyan-500/10 text-cyan-200'
    : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200';

  if (!description) {
    return <span>{item}</span>;
  }

  return (
    <span className="flex flex-col gap-2">
      <span className={`w-fit rounded-md border px-2 py-1 text-xs font-bold uppercase tracking-wider ${color}`}>
        {label}
      </span>
      <span>{description}</span>
    </span>
  );
};

const SectionBlock: React.FC<{ section: (typeof GENAI_DATA_SECURITY_OVERVIEW)[number] }> = ({ section }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <section id={section.id} className="scroll-mt-8 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70">
      <button
        type="button"
        onClick={() => setIsExpanded((current) => !current)}
        className="flex w-full items-start justify-between gap-3 p-4 text-left sm:gap-4 md:p-6"
      >
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-1 rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-2">
            <BookOpen className="h-4 w-4 text-cyan-300" />
          </div>
          <div className="min-w-0">
            <h2 className="break-words text-xl font-bold text-white md:text-2xl">{section.title}</h2>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
              Expand to view the GenAI data-security definition, protected data classes, and security posture emphasis.
            </p>
          </div>
        </div>
        <ChevronDown className={`mt-2 h-6 w-6 shrink-0 text-slate-500 transition-transform ${isExpanded ? 'rotate-180 text-cyan-300' : ''}`} />
      </button>

      {isExpanded && (
        <div className="border-t border-slate-800 p-4 md:p-6">
          {section.body && (
            <div className="space-y-3 text-sm leading-relaxed text-slate-300 md:text-base">
              {section.body.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </div>
          )}

          {section.bullets && (
            <ul className="mt-5 grid gap-3 md:grid-cols-2">
              {section.bullets.map((item) => (
                <li key={item} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-300">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          )}

          {section.subsections && (
            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              {section.subsections.map((subsection) => (
                <div key={subsection.title} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                  <h3 className="mb-3 text-base font-bold text-slate-100">{subsection.title}</h3>
                  {subsection.body && (
                    <div className="mb-3 space-y-2 text-sm leading-relaxed text-slate-400">
                      {subsection.body.map((paragraph) => (
                        <p key={paragraph}>{paragraph}</p>
                      ))}
                    </div>
                  )}
                  {subsection.bullets && (
                    <ul className="space-y-2">
                      {subsection.bullets.map((item) => (
                        <li key={item} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-sm leading-relaxed text-slate-300">
                          <CheckCircle2 className={`mt-1 h-4 w-4 shrink-0 ${subsection.title === 'Protect These Data Classes' ? 'text-cyan-300' : 'text-emerald-300'}`} />
                          <HighlightedBullet
                            item={item}
                            accent={subsection.title === 'Protect These Data Classes' ? 'cyan' : 'emerald'}
                          />
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
};

const DspmSection: React.FC = () => {
  const [expandedId, setExpandedId] = useState<string | null>(GENAI_DSPM_CAPABILITIES[0]?.id || null);

  return (
    <section id="ai-dspm" className="scroll-mt-8 rounded-xl border border-slate-800 bg-slate-900/70 p-4 md:p-6">
      <div className="mb-5 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-1 rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-2">
            <Database className="h-4 w-4 text-emerald-300" />
          </div>
          <div className="min-w-0">
            <h2 className="break-words text-xl font-bold text-white md:text-2xl">DSPM for GenAI (AI-DSPM)</h2>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
              AI-DSPM is the continuous practice of discovering, classifying, governing,
              monitoring, and enforcing data controls across GenAI pipelines and runtimes.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setExpandedId(expandedId ? null : GENAI_DSPM_CAPABILITIES[0]?.id || null)}
          className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-emerald-500/30 hover:text-emerald-200 sm:w-auto"
        >
          <ChevronDown className={`h-4 w-4 transition-transform ${expandedId ? 'rotate-180' : ''}`} />
          {expandedId ? 'Collapse card' : 'Open first card'}
        </button>
      </div>

      <div className="mb-5 grid gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
          <div className="mb-2 inline-flex rounded-md border border-blue-500/25 bg-blue-500/10 px-2 py-1 text-xs font-bold uppercase tracking-wider text-blue-200">
            Extend DSPM
          </div>
          <p className="text-sm leading-relaxed text-slate-300">
            Extends existing data-security posture management to GenAI-adjacent stores, identities,
            lineage, access paths, and policy bindings.
          </p>
        </div>
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4">
          <div className="mb-2 inline-flex rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2 py-1 text-xs font-bold uppercase tracking-wider text-emerald-200">
            GenAI Specific DSPM
          </div>
          <p className="text-sm leading-relaxed text-slate-300">
            Adds posture controls unique to GenAI runtimes: prompts, RAG, vector stores, telemetry,
            tools, model training, agents, shadow AI, and derived artifacts.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {GENAI_DSPM_CAPABILITIES.map((capability) => {
          const isExpanded = expandedId === capability.id;
          const isExtend = capability.category === 'Extend DSPM';
          const color = isExtend
            ? 'border-blue-500/25 bg-blue-500/10 text-blue-200'
            : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200';
          const activeBorder = isExtend ? 'border-blue-500/30' : 'border-emerald-500/30';
          return (
            <article
              key={capability.id}
              className={`overflow-hidden rounded-xl border bg-slate-950/50 transition-all duration-300 ${
                isExpanded ? `${activeBorder} shadow-lg shadow-black/20` : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <button
                type="button"
                onClick={() => setExpandedId(isExpanded ? null : capability.id)}
                className="flex w-full items-start justify-between gap-3 p-4 text-left sm:items-center sm:gap-4"
              >
                <div className="flex min-w-0 flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                  <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${isExtend ? 'bg-blue-400' : 'bg-emerald-400'}`} />
                  <span className="font-mono text-xs text-slate-500">{capability.id.replace('ai-dspm-', '#')}</span>
                  <h3 className="break-words text-base font-bold leading-snug text-white">{capability.title}</h3>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <span className="hidden text-xs text-slate-500 sm:inline">Click to inspect</span>
                  <ChevronDown className={`h-5 w-5 text-slate-500 transition-transform ${isExpanded ? 'rotate-180 text-cyan-300' : ''}`} />
                </div>
              </button>

              <div className={isExpanded ? 'block' : 'hidden'}>
                <div className="border-t border-slate-800 p-4">
                  <div className={`mb-3 inline-flex rounded-md border px-2 py-1 text-[11px] font-bold uppercase tracking-wider ${color}`}>
                    {capability.category}
                  </div>
                  <div className="mb-4 rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <div className="mb-1 text-xs font-bold uppercase tracking-wider text-slate-500">Objective</div>
                    <p className="text-sm leading-relaxed text-slate-300">{capability.objective}</p>
                  </div>
                  <div className="text-xs font-bold uppercase tracking-wider text-slate-500">Actions</div>
                  <ul className="mt-2 grid gap-2 lg:grid-cols-2">
                    {capability.actions.map((action) => (
                      <li key={action} className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900/50 p-3 text-sm leading-relaxed text-slate-300">
                        <span className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${isExtend ? 'bg-blue-400' : 'bg-emerald-400'}`} />
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
};

const TierBadge: React.FC<{ tier: GenAiDataSecurityTier; label: string }> = ({ tier, label }) => {
  const color = tier === 1 ? 'emerald' : tier === 2 ? 'cyan' : 'purple';
  const classes = {
    emerald: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    cyan: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
    purple: 'border-purple-500/30 bg-purple-500/10 text-purple-200'
  }[color];
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-bold ${classes}`}>
      Tier {tier}: {label}
    </span>
  );
};

const RiskCard: React.FC<{
  risk: GenAiDataSecurityRisk;
  isExpanded: boolean;
  selectedTier: GenAiDataSecurityTier | 'All';
  onToggle: () => void;
  onNavigateToOwasp?: (threatId: string) => void;
}> = ({ risk, isExpanded, selectedTier, onToggle, onNavigateToOwasp }) => {
  const style = THEME_STYLES[risk.theme];
  const visibleMitigations =
    selectedTier === 'All'
      ? risk.mitigations
      : risk.mitigations.filter((group) => group.tier === selectedTier);

  return (
    <article
      id={risk.id}
      className={`scroll-mt-20 sm:scroll-mt-24 overflow-hidden rounded-xl border bg-slate-900/70 transition-colors ${
        isExpanded ? style.border : 'border-slate-800 hover:border-slate-700'
      }`}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start justify-between gap-3 p-4 text-left sm:gap-4 md:p-5"
      >
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs font-bold text-slate-300">
              {risk.id}
            </span>
            <span className={`rounded-full border px-3 py-1 text-xs font-bold ${style.badge}`}>
              {risk.theme}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-400">
              {risk.mitigations.reduce((count, group) => count + group.items.length, 0)} controls
            </span>
            {risk.mitreAtlasRefs && risk.mitreAtlasRefs.length > 0 && onNavigateToOwasp && (
              risk.mitreAtlasRefs.map(techId => (
                <button
                  key={techId}
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onNavigateToOwasp(techId);
                  }}
                  className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-xs font-mono font-bold text-rose-300 hover:bg-rose-500/20 hover:border-rose-400 transition-all cursor-pointer"
                  title={`Jump to MITRE ATLAS Technique ${techId}`}
                >
                  <ShieldCheck className="w-3 h-3 text-rose-400" />
                  {techId}
                </button>
              ))
            )}
          </div>
          <h3 className="break-words text-lg font-bold text-white md:text-xl">{risk.title}</h3>
          <p className={`mt-2 text-sm leading-relaxed text-slate-400 ${isExpanded ? '' : 'line-clamp-2'}`}>
            {risk.summary}
          </p>
        </div>
        <ChevronDown className={`mt-2 h-6 w-6 shrink-0 text-slate-500 transition-transform ${isExpanded ? 'rotate-180 text-cyan-300' : ''}`} />
      </button>

      {isExpanded && (
        <div className="border-t border-slate-800/70 p-4 md:p-5 animate-in fade-in duration-200">
          <div className="space-y-5">
            <div>
              <h4 className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                How the Attack Unfolds
              </h4>
              <ul className="space-y-2">
                {risk.howItUnfolds.map((item) => (
                  <li key={item} className="rounded-lg border border-orange-500/10 bg-orange-500/5 p-3 text-sm leading-relaxed text-slate-300">
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h4 className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
                <Target className="h-4 w-4 text-red-400" />
                Attacker Capabilities
              </h4>
              <ul className="space-y-2">
                {risk.attackerCapabilities.map((item) => (
                  <li key={item} className="flex items-start gap-3 rounded-lg border border-red-500/10 bg-red-500/5 p-3 text-sm leading-relaxed text-slate-300">
                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-red-400" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
              <h4 className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-300">Illustrative Scenario</h4>
              <p className="text-sm leading-relaxed text-slate-300">{risk.illustrativeScenario}</p>
            </div>

            <div>
              <h4 className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
                <Layers className="h-4 w-4 text-purple-400" />
                Impact
              </h4>
              <ul className="space-y-2">
                {risk.impacts.map((item) => (
                  <li key={item} className="flex items-start gap-3 rounded-lg border border-purple-500/10 bg-purple-500/5 p-3 text-sm leading-relaxed text-slate-300">
                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-purple-400" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h4 className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Tiered Mitigations
              </h4>
              <div className="space-y-3">
                {visibleMitigations.map((group) => (
                  <div key={group.tier} className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <TierBadge tier={group.tier} label={group.label} />
                    </div>
                    <p className="mb-3 text-sm leading-relaxed text-slate-400">{group.intent}</p>
                    <ul className="space-y-2">
                      {group.items.map((item) => (
                        <li key={`${group.tier}-${item.title}`} className="rounded-lg border border-emerald-500/10 bg-emerald-500/5 p-3">
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <span className="min-w-0 break-words text-sm font-bold text-emerald-100">{item.title}</span>
                            {item.scope && (
                              <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-400">
                                {item.scope}
                              </span>
                            )}
                          </div>
                          <p className="mt-1 text-sm leading-relaxed text-slate-300">{item.description}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {(risk.knownExploits?.length || risk.references?.length || risk.crossReferences?.length) && (
            <div className="mt-5 grid gap-4 lg:grid-cols-3">
              {risk.knownExploits && risk.knownExploits.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <h4 className="mb-3 text-sm font-bold uppercase tracking-wider text-slate-300">Known CVEs / Exploits</h4>
                  <ul className="space-y-2">
                    {risk.knownExploits.map((item) => (
                      <li key={item} className="text-sm leading-relaxed text-slate-400">{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {risk.references && risk.references.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <h4 className="mb-3 text-sm font-bold uppercase tracking-wider text-slate-300">References</h4>
                  <div className="space-y-2">
                    {risk.references.map((reference) => (
                      <a
                        key={reference.url}
                        href={reference.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex min-w-0 items-start gap-2 rounded-lg border border-slate-800 bg-slate-900/70 p-2 text-sm text-cyan-300 hover:border-cyan-500/30 hover:text-cyan-200"
                      >
                        <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <span className="min-w-0 break-words">{reference.title}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {((risk.crossReferences && risk.crossReferences.length > 0) || (risk.mitreAtlasRefs && risk.mitreAtlasRefs.length > 0)) && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <h4 className="mb-3 text-sm font-bold uppercase tracking-wider text-slate-300">Cross References & ATLAS</h4>
                  <div className="space-y-2">
                    {risk.mitreAtlasRefs && risk.mitreAtlasRefs.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mb-2">
                        {risk.mitreAtlasRefs.map(techId => (
                          <button
                            key={techId}
                            type="button"
                            onClick={() => onNavigateToOwasp && onNavigateToOwasp(techId)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-rose-500/30 bg-rose-500/10 text-xs font-mono font-bold text-rose-300 hover:bg-rose-500/20 hover:border-rose-400 transition-all cursor-pointer"
                            title={`Explore ${techId} in MITRE ATLAS Matrix`}
                          >
                            <span>{techId}</span>
                            <ExternalLink className="w-3 h-3 text-rose-400" />
                          </button>
                        ))}
                      </div>
                    )}
                    {risk.crossReferences && risk.crossReferences.map((item) => (
                      <div key={item} className="text-sm leading-relaxed text-slate-400">{item}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  );
};

interface GenAiDataSecurityViewProps {
  initialExpandedId?: string | null;
  onNavigateToOwasp?: (threatId: string) => void;
}

const normalizeRiskId = (id: string | null | undefined): string | null => {
  if (!id) return null;
  const upper = id.trim().toUpperCase();
  const match = upper.match(/^DSGAI-?(\d{1,2})$/);
  if (match) {
    const num = match[1].padStart(2, '0');
    return `DSGAI${num}`;
  }
  return id.trim();
};

const GenAiDataSecurityView: React.FC<GenAiDataSecurityViewProps> = ({ initialExpandedId, onNavigateToOwasp }) => {
  const [activeSectionId, setActiveSectionId] = useState('genai-data-security-context');
  const [search, setSearch] = useState('');
  const [themeFilter, setThemeFilter] = useState<ThemeFilter>('All');
  const [tierFilter, setTierFilter] = useState<GenAiDataSecurityTier | 'All'>('All');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>(() => {
    const norm = normalizeRiskId(initialExpandedId);
    if (norm) {
      return { [norm]: true };
    }
    return { DSGAI01: true };
  });

  const scrollToSection = (id: string) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const el = document.getElementById(id);
        if (el) {
          const headerOffset = window.innerWidth < 768 ? 72 : 88;
          const elementTop = el.getBoundingClientRect().top + window.pageYOffset;
          window.scrollTo({
            top: Math.max(0, elementTop - headerOffset),
            behavior: 'smooth'
          });
        }
      });
    });
  };
  const scrollToRisk = scrollToSection;

  useEffect(() => {
    if (initialExpandedId) {
      const norm = normalizeRiskId(initialExpandedId) || initialExpandedId;
      setExpandedIds((prev) => ({ ...prev, [norm]: true }));
      scrollToSection(norm);
    }
  }, [initialExpandedId]);

  const themes = useMemo(
    () => ['All', ...Array.from(new Set(GENAI_DATA_SECURITY_RISKS.map((risk) => risk.theme)))] as ThemeFilter[],
    []
  );

  const filteredRisks = useMemo(() => {
    return GENAI_DATA_SECURITY_RISKS.filter((risk) => {
      const themeMatches = themeFilter === 'All' || risk.theme === themeFilter;
      return themeMatches && includesSearch(risk, search);
    });
  }, [search, themeFilter]);

  const areFilteredRisksExpanded = filteredRisks.length > 0
    && filteredRisks.every((risk) => Boolean(expandedIds[risk.id]));

  const tocItems = useMemo(() => {
    const overviewItems = GENAI_DATA_SECURITY_OVERVIEW.map((section) => ({
      label: section.title,
      targetId: section.id,
    }));
    return [
      ...overviewItems,
      { label: 'AI-DSPM Capabilities', targetId: 'ai-dspm' },
      { label: 'DSGAI Risk Navigator', targetId: 'risk-navigator' },
    ];
  }, []);

  useEffect(() => {
    const getTrackedElements = () => [
      ...tocItems.map((item) => document.getElementById(item.targetId)),
      ...filteredRisks.map((risk) => document.getElementById(risk.id)),
    ].filter((element): element is HTMLElement => Boolean(element));

    let animationFrame = 0;

    const updateActiveSection = () => {
      const sectionElements = getTrackedElements()
        .map((element) => ({
          id: element.id,
          top: element.getBoundingClientRect().top + window.scrollY,
        }))
        .sort((a, b) => a.top - b.top);

      if (sectionElements.length === 0) return;

      const activationLine = window.scrollY + 170;
      const activeElement = sectionElements.reduce(
        (current, candidate) => candidate.top <= activationLine ? candidate : current,
        sectionElements[0]
      );

      setActiveSectionId(activeElement.id);
    };

    const requestUpdate = () => {
      window.cancelAnimationFrame(animationFrame);
      animationFrame = window.requestAnimationFrame(updateActiveSection);
    };

    window.addEventListener('scroll', requestUpdate, { passive: true });
    window.addEventListener('resize', requestUpdate, { passive: true });
    updateActiveSection();

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener('scroll', requestUpdate);
      window.removeEventListener('resize', requestUpdate);
    };
  }, [tocItems, filteredRisks]);

  const toggleRisk = (id: string) => {
    const isOpening = !expandedIds[id];
    setExpandedIds((current) => ({
      ...current,
      [id]: isOpening,
    }));
    if (isOpening) {
      scrollToRisk(id);
    }
  };

  const clearFilters = () => {
    setSearch('');
    setThemeFilter('All');
    setTierFilter('All');
  };

  return (
    <div className="container-fluid mx-auto max-w-7xl animate-in fade-in duration-500 overflow-hidden p-3 sm:p-4 md:p-8">
      <div className="mb-6 rounded-xl border border-cyan-500/20 bg-slate-900/70 p-4 sm:p-6 md:mb-8 md:rounded-2xl md:p-8">
        <div className="mb-5 flex flex-wrap items-center gap-2">
          <span className="inline-flex max-w-full items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wider text-cyan-300 sm:text-xs">
            <Database className="h-3.5 w-3.5" />
            <span className="truncate">GenAI Data Security</span>
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {GENAI_DATA_SECURITY_META.version}
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {GENAI_DATA_SECURITY_META.publicationDate}
          </span>
        </div>

        <h1 className="max-w-5xl break-words text-2xl font-bold text-white sm:text-3xl md:text-5xl">
          {GENAI_DATA_SECURITY_META.title}
        </h1>
        <p className="mt-4 max-w-4xl text-sm leading-relaxed text-slate-400 md:text-base">
          Interactive guide to OWASP GenAI Data Security—featuring 21 risk deep-dives and 13 AI-DSPM capabilities to govern LLM pipelines, RAG stores, agent memory, and multimodal datasets.
        </p>

        <div className="mt-6">
          <div className="max-w-xl rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <FileText className="h-4 w-4 text-cyan-300" />
              Source
            </div>
            <div className="space-y-2 text-sm text-slate-400">
              <a
                href={GENAI_DATA_SECURITY_META.resourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex max-w-full min-w-0 items-center gap-1 text-cyan-300 hover:text-cyan-200"
              >
                <span className="min-w-0 break-words">{GENAI_DATA_SECURITY_META.site}</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[300px_minmax(0,1fr)] lg:gap-8">
        <aside className="lg:sticky lg:top-8 lg:self-start">
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-3 md:p-4">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <FileText className="h-4 w-4 text-cyan-300" />
              Navigator
            </div>
            <nav className="flex gap-2 overflow-x-auto pb-1 lg:block lg:space-y-1 lg:overflow-visible lg:pb-0">
              {tocItems.map((item) => {
                const isRiskEntryActive = GENAI_DATA_SECURITY_RISKS.some((risk) => risk.id === activeSectionId);
                const isActive = activeSectionId === item.targetId
                  || (item.targetId === 'risk-navigator' && isRiskEntryActive);
                return (
                  <button
                    key={item.targetId}
                    type="button"
                    onClick={() => scrollToSection(item.targetId)}
                    className={`block w-full text-left shrink-0 rounded-md border px-3 py-2 text-sm transition-colors lg:shrink lg:whitespace-normal cursor-pointer ${
                      isActive
                        ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                        : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    {item.label}
                  </button>
                );
              })}
            </nav>

            <div className="mt-5 border-t border-slate-800 pt-4">
              <div className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
                <Sparkles className="h-4 w-4 text-cyan-300" />
                Risk Index
              </div>
              <div className="flex gap-2 overflow-x-auto pb-1 lg:block lg:max-h-[320px] lg:space-y-1 lg:overflow-y-auto lg:pb-0 lg:pr-1" style={{ scrollbarGutter: 'stable' }}>
                {filteredRisks.map((risk) => {
                  const isActive = activeSectionId === risk.id;
                  const style = THEME_STYLES[risk.theme];
                  return (
                    <button
                      key={risk.id}
                      type="button"
                      onClick={() => {
                        setExpandedIds((current) => ({ ...current, [risk.id]: true }));
                        scrollToSection(risk.id);
                      }}
                      className={`flex w-full text-left min-w-[12rem] items-center gap-2 rounded-md border px-2 py-2 text-xs transition-colors lg:min-w-0 cursor-pointer ${
                        isActive
                          ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                          : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-white'
                      }`}
                    >
                      <span className={`h-2 w-2 shrink-0 rounded-full ${style.dot}`} />
                      <span className="font-mono">{risk.id}</span>
                      <span className="truncate">{risk.title}</span>
                    </button>
                  );
                })}
                {filteredRisks.length === 0 && (
                  <div className="rounded-md border border-slate-800 bg-slate-950 px-3 py-3 text-xs text-slate-500">
                    No matching risks
                  </div>
                )}
              </div>
            </div>
          </div>
        </aside>

        <div className="min-w-0 space-y-5 md:space-y-6">
          {GENAI_DATA_SECURITY_OVERVIEW.map((section) => (
            <SectionBlock key={section.id} section={section} />
          ))}

          <DspmSection />

          <section id="risk-navigator" className="scroll-mt-8 rounded-xl border border-slate-800 bg-slate-900/70 p-4 md:p-6">
            <div className="mb-5 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
              <div>
                <h2 className="text-xl font-bold text-white md:text-2xl">DSGAI Risk Navigator</h2>
                <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
                  Search across the published DSGAI entries, filter by risk theme, and focus the mitigation view
                  on foundational, hardening, or advanced controls.
                </p>
              </div>

              <button
                type="button"
                onClick={() => {
                  setExpandedIds((current) => {
                    const nextState = { ...current };
                    filteredRisks.forEach((risk) => {
                      nextState[risk.id] = !areFilteredRisksExpanded;
                    });
                    return nextState;
                  });
                }}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-cyan-500/30 hover:text-cyan-200 sm:w-auto"
              >
                <ChevronDown className="h-4 w-4" />
                {areFilteredRisksExpanded ? 'Minimize all' : 'Expand all'}
              </button>
            </div>

            <div className="mb-5 grid gap-3 xl:grid-cols-[1fr_220px_170px_auto]">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search risks, controls, CVEs, keywords..."
                  className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-3 text-sm text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500/50"
                />
              </div>

              <label className="relative">
                <Filter className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <select
                  value={themeFilter}
                  onChange={(event) => setThemeFilter(event.target.value as ThemeFilter)}
                  className="h-10 w-full appearance-none rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-3 text-sm text-slate-200 outline-none transition-colors focus:border-cyan-500/50"
                >
                  {themes.map((theme) => (
                    <option key={theme} value={theme}>{theme}</option>
                  ))}
                </select>
              </label>

              <label className="relative">
                <ListChecks className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <select
                  value={tierFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setTierFilter(value === 'All' ? 'All' : Number(value) as GenAiDataSecurityTier);
                  }}
                  className="h-10 w-full appearance-none rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-3 text-sm text-slate-200 outline-none transition-colors focus:border-cyan-500/50"
                >
                  <option value="All">All tiers</option>
                  <option value="1">Tier 1</option>
                  <option value="2">Tier 2</option>
                  <option value="3">Tier 3</option>
                </select>
              </label>

              <button
                type="button"
                onClick={clearFilters}
                className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 text-sm text-slate-300 hover:border-cyan-500/30 hover:text-cyan-200"
              >
                <X className="h-4 w-4" />
                Clear
              </button>
            </div>

            <div className="mb-4 flex flex-wrap gap-2">
              {themes.filter((theme) => theme !== 'All').map((theme) => {
                const count = GENAI_DATA_SECURITY_RISKS.filter((risk) => risk.theme === theme).length;
                const style = THEME_STYLES[theme as GenAiDataSecurityRisk['theme']];
                return (
                  <button
                    key={theme}
                    type="button"
                    onClick={() => setThemeFilter(theme)}
                    className={`rounded-full border px-3 py-1.5 text-xs font-bold transition-colors ${
                      themeFilter === theme
                        ? style.badge
                        : 'border-slate-700 bg-slate-950 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                    }`}
                  >
                    {style.label} ({count})
                  </button>
                );
              })}
            </div>

            <div className="mb-5 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-400">
              Showing <span className="font-bold text-white">{filteredRisks.length}</span> of{' '}
              <span className="font-bold text-white">{GENAI_DATA_SECURITY_RISKS.length}</span> DSGAI risks.
            </div>

            <div className="space-y-4">
              {filteredRisks.map((risk) => (
                <RiskCard
                  key={risk.id}
                  risk={risk}
                  isExpanded={Boolean(expandedIds[risk.id])}
                  selectedTier={tierFilter}
                  onToggle={() => toggleRisk(risk.id)}
                  onNavigateToOwasp={onNavigateToOwasp}
                />
              ))}
              {filteredRisks.length === 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-8 text-center text-slate-400">
                  No risks match the current search and filters.
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default GenAiDataSecurityView;

import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ExternalLink,
  FileText,
  ListChecks,
  Network,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Wrench,
  X,
} from 'lucide-react';
import {
  SECURE_MCP_GUIDE_META,
  SECURE_MCP_GUIDE_SECTIONS,
  SECURE_MCP_MINIMUM_BAR,
  SecureMcpGuideSection,
  SecureMcpGuideSubsection,
} from '../data_secure_mcp_guide';

const CONTROL_FAMILIES = [
  {
    title: 'Architecture',
    description: 'Choose safe local/remote transport, isolate execution, and prevent residual state from crossing sessions.',
    match: ['architecture', 'connection', 'session', 'isolate', 'local', 'remote']
  },
  {
    title: 'Tool Safety',
    description: 'Treat every tool definition, manifest, schema, and behavior change as a security-sensitive interface.',
    match: ['tool', 'manifest', 'approval', 'description', 'behavior']
  },
  {
    title: 'Validation',
    description: 'Force model intent through schemas, size limits, sanitization, and resource quotas before anything executes.',
    match: ['validation', 'resource', 'schema', 'sanitize', 'quota']
  },
  {
    title: 'Prompt Injection',
    description: 'Separate instructions from data, reset context between tasks, and require review for high-impact actions.',
    match: ['prompt', 'injection', 'hitl', 'judge', 'session']
  },
  {
    title: 'Identity',
    description: 'Use real authentication, scoped delegation, short-lived tokens, and centralized authorization decisions.',
    match: ['authentication', 'authorization', 'oauth', 'token', 'identity']
  },
  {
    title: 'Operations',
    description: 'Harden deployment, scan supply chain dependencies, monitor runtime behavior, and keep immutable audit trails.',
    match: ['deployment', 'updates', 'governance', 'tools', 'continuous', 'audit', 'supply']
  }
];

const VISIBLE_SECURE_MCP_SECTIONS = SECURE_MCP_GUIDE_SECTIONS.filter(
  (section) => section.id !== 'introduction-background'
);

const normalize = (value: string) => value.toLowerCase();

const extractLead = (item: string) => {
  const [lead, ...rest] = item.split(':');
  return rest.length > 0
    ? { lead, detail: rest.join(':').trim() }
    : { lead: '', detail: item };
};

const sectionMatchesSearch = (section: SecureMcpGuideSection, search: string) => {
  const term = normalize(search.trim());
  if (!term) return true;
  const haystack = [
    section.title,
    ...(section.body || []),
    ...(section.bullets || []),
    ...(section.subsections || []).flatMap((subsection) => [
      subsection.title,
      ...(subsection.body || []),
      ...(subsection.bullets || [])
    ])
  ].join(' ').toLowerCase();
  return haystack.includes(term);
};

const ListBlock: React.FC<{ items: string[]; tone?: 'cyan' | 'emerald' }> = ({ items, tone = 'cyan' }) => (
  <ul className="space-y-2">
    {items.map((item) => {
      const { lead, detail } = extractLead(item);
      return (
        <li
          key={item}
          className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm leading-relaxed text-slate-300"
        >
          <div className="flex items-start gap-3">
            <CheckCircle2 className={`mt-0.5 h-4 w-4 shrink-0 ${tone === 'cyan' ? 'text-cyan-300' : 'text-emerald-300'}`} />
            <div className="min-w-0">
              {lead && (
                <div className={`mb-1 inline-flex rounded-md border px-2 py-1 text-xs font-bold uppercase tracking-wider ${
                  tone === 'cyan'
                    ? 'border-cyan-500/25 bg-cyan-500/10 text-cyan-200'
                    : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200'
                }`}>
                  {lead}
                </div>
              )}
              <div className="break-words">{detail}</div>
            </div>
          </div>
        </li>
      );
    })}
  </ul>
);

const SubsectionCard: React.FC<{ subsection: SecureMcpGuideSubsection }> = ({ subsection }) => (
  <article className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
    <h4 className="break-words text-base font-bold text-white">{subsection.title}</h4>
    {subsection.body && (
      <div className="mt-3 space-y-2 text-sm leading-relaxed text-slate-300">
        {subsection.body.map((paragraph) => (
          <p key={paragraph}>{paragraph}</p>
        ))}
      </div>
    )}
    {subsection.bullets && (
      <div className={subsection.body ? 'mt-4' : 'mt-3'}>
        <ListBlock items={subsection.bullets} />
      </div>
    )}
  </article>
);

const GuideSection: React.FC<{
  section: SecureMcpGuideSection;
  isExpanded: boolean;
  onToggle: () => void;
}> = ({ section, isExpanded, onToggle }) => {
  return (
    <section
      id={section.id}
      className={`scroll-mt-8 overflow-hidden rounded-xl border bg-slate-900/70 transition-colors ${
        isExpanded ? 'border-cyan-500/30' : 'border-slate-800 hover:border-slate-700'
      }`}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start justify-between gap-3 p-4 text-left sm:gap-4 md:p-6"
      >
        <div className="min-w-0">
          <h2 className="break-words text-xl font-bold text-white md:text-2xl">{section.title}</h2>
          {section.body?.[0] && (
            <p className={`mt-2 text-sm leading-relaxed text-slate-400 ${isExpanded ? '' : 'line-clamp-2'}`}>
              {section.body[0]}
            </p>
          )}
        </div>
        <ChevronDown className={`mt-2 h-6 w-6 shrink-0 text-slate-500 transition-transform ${isExpanded ? 'rotate-180 text-cyan-300' : ''}`} />
      </button>

      {isExpanded && (
        <div className="border-t border-slate-800 p-4 md:p-6">
          {section.body && section.body.length > 0 && (
            <div className="space-y-3 text-sm leading-relaxed text-slate-300 md:text-base">
              {section.body.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </div>
          )}

          {section.bullets && (
            <div className={section.body ? 'mt-5' : ''}>
              <ListBlock items={section.bullets} />
            </div>
          )}

          {section.subsections && (
            <div className="mt-5 grid gap-4">
              {section.subsections.map((subsection) => (
                <SubsectionCard
                  key={subsection.title}
                  subsection={subsection}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
};

const SecureMcpGuideView: React.FC = () => {
  const meta = SECURE_MCP_GUIDE_META;
  const checklistItems = useMemo(
    () => SECURE_MCP_MINIMUM_BAR.flatMap((group) => group.items),
    []
  );
  const [checkedItems, setCheckedItems] = useState<Record<string, boolean>>({});
  const [search, setSearch] = useState('');
  const [activeSectionId, setActiveSectionId] = useState(VISIBLE_SECURE_MCP_SECTIONS[0]?.id || '');
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    [VISIBLE_SECURE_MCP_SECTIONS[0]?.id || '']: true,
  });

  const filteredSections = useMemo(
    () => VISIBLE_SECURE_MCP_SECTIONS.filter((section) => sectionMatchesSearch(section, search)),
    [search]
  );

  const areFilteredSectionsExpanded = filteredSections.length > 0
    && filteredSections.every((section) => expandedSections[section.id]);

  useEffect(() => {
    const getTrackedElements = () => [
      ...filteredSections.map((section) => document.getElementById(section.id)),
      document.getElementById('minimum-bar'),
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

    updateActiveSection();
    window.addEventListener('scroll', requestUpdate, { passive: true });
    window.addEventListener('resize', requestUpdate);

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener('scroll', requestUpdate);
      window.removeEventListener('resize', requestUpdate);
    };
  }, [filteredSections]);

  const checkedCount = checklistItems.filter((item) => checkedItems[item]).length;
  const completionPercent = checklistItems.length > 0
    ? Math.round((checkedCount / checklistItems.length) * 100)
    : 0;

  const toggleChecklistItem = (item: string) => {
    setCheckedItems((current) => ({
      ...current,
      [item]: !current[item]
    }));
  };

  const toggleSection = (id: string) => {
    setExpandedSections((current) => ({
      ...current,
      [id]: !current[id]
    }));
  };

  const toggleFilteredSections = () => {
    setExpandedSections((current) => {
      const next = { ...current };
      filteredSections.forEach((section) => {
        next[section.id] = !areFilteredSectionsExpanded;
      });
      return next;
    });
  };

  const clearSearch = () => setSearch('');

  return (
    <div className="container-fluid mx-auto max-w-7xl animate-in fade-in duration-500 overflow-hidden p-3 sm:p-4 md:p-8">
      <div className="mb-6 rounded-xl border border-cyan-500/20 bg-slate-900/70 p-4 sm:p-6 md:mb-8 md:rounded-2xl md:p-8">
        <div className="mb-5 flex flex-wrap items-center gap-2">
          <span className="inline-flex max-w-full items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wider text-cyan-300 sm:text-xs">
            <Network className="h-3.5 w-3.5" />
            <span className="truncate">Secure MCP Development</span>
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {meta.version}
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {meta.publicationDate}
          </span>
        </div>

        <h1 className="max-w-5xl break-words text-2xl font-bold text-white sm:text-3xl md:text-5xl">
          {meta.title}
        </h1>
        <p className="mt-4 max-w-4xl text-sm leading-relaxed text-slate-400 md:text-base">
          Practical hardening guide and readiness checklist for platform engineers and security teams building on the Model Context Protocol. Explore each control family to implement defense-in-depth against tool abuse, data exfiltration, and confused-deputy attacks.
        </p>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {CONTROL_FAMILIES.map((family) => (
            <a
              key={family.title}
              href={`#${SECURE_MCP_GUIDE_SECTIONS.find((section) => family.match.some((term) => normalize(section.title).includes(term)))?.id || 'minimum-bar'}`}
              className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 transition-colors hover:border-cyan-500/30"
            >
              <div className="mb-2 flex min-w-0 items-center gap-2 text-sm font-bold text-white">
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
                <span className="min-w-0 break-words">{family.title}</span>
              </div>
              <p className="text-sm leading-relaxed text-slate-400">{family.description}</p>
            </a>
          ))}
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-[1.35fr_0.65fr]">
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-amber-300">
              <AlertTriangle className="h-4 w-4" />
              How to Use This Page
            </div>
            <p className="text-sm leading-relaxed text-slate-300">
              Start with the concept map, search for the control you need, expand the matching section,
              and then use the minimum bar checklist to track implementation readiness.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <BookOpen className="h-4 w-4 text-cyan-300" />
              Source
            </div>
            <a
              href={meta.resourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex max-w-full min-w-0 items-center gap-1 text-sm text-cyan-300 hover:text-cyan-200"
            >
              <span className="min-w-0 break-words">{meta.site}</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
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
              {filteredSections.map((section) => {
                const isActive = activeSectionId === section.id;
                return (
                  <a
                    key={section.id}
                    href={`#${section.id}`}
                    onClick={() => setExpandedSections((current) => ({ ...current, [section.id]: true }))}
                    className={`block shrink-0 rounded-md border px-3 py-2 text-sm transition-colors lg:shrink lg:whitespace-normal ${
                      isActive
                        ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                        : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    {section.title}
                  </a>
                );
              })}
              <a
                href="#minimum-bar"
                className={`block shrink-0 rounded-md border px-3 py-2 text-sm transition-colors lg:shrink lg:whitespace-normal ${
                  activeSectionId === 'minimum-bar'
                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                    : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
              >
                MCP Security Minimum Bar
              </a>
            </nav>
          </div>
        </aside>

        <div className="min-w-0 space-y-5 md:space-y-6">
          <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 md:p-6">
            <div className="mb-4 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
              <div>
                <h2 className="text-xl font-bold text-white md:text-2xl">Secure MCP Control Explorer</h2>
                <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
                  Filter the guide by concept, open only what matters now, and keep the details available
                  when you need to go deeper.
                </p>
              </div>
              <button
                type="button"
                onClick={toggleFilteredSections}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-cyan-500/30 hover:text-cyan-200 sm:w-auto"
              >
                <ChevronDown className="h-4 w-4" />
                {areFilteredSectionsExpanded ? 'Collapse all' : 'Expand all'}
              </button>
            </div>

            <div className="grid gap-3 xl:grid-cols-[1fr_auto]">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search architecture, tools, OAuth, prompt injection, validation..."
                  className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-3 text-sm text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500/50"
                />
              </div>
              <button
                type="button"
                onClick={clearSearch}
                className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 text-sm text-slate-300 hover:border-cyan-500/30 hover:text-cyan-200"
              >
                <X className="h-4 w-4" />
                Clear
              </button>
            </div>

            <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-400">
              Showing <span className="font-bold text-white">{filteredSections.length}</span> of{' '}
              <span className="font-bold text-white">{VISIBLE_SECURE_MCP_SECTIONS.length}</span> guide sections.
            </div>
          </section>

          {filteredSections.map((section, index) => (
            <GuideSection
              key={section.id}
              section={section}
              isExpanded={Boolean(expandedSections[section.id])}
              onToggle={() => toggleSection(section.id)}
            />
          ))}

          {filteredSections.length === 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-8 text-center text-slate-400">
              No Secure MCP guide sections match the current search.
            </div>
          )}

          <section
            id="minimum-bar"
            className="scroll-mt-8 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 md:p-6"
          >
            <div className="mb-5 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div className="flex min-w-0 items-start gap-3">
                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-2">
                  <ListChecks className="h-5 w-5 text-emerald-300" />
                </div>
                <div className="min-w-0">
                  <h2 className="break-words text-xl font-bold text-white md:text-2xl">
                    MCP Security Minimum Bar
                  </h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Use this as an implementation readiness tracker for production MCP servers.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCheckedItems({})}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-emerald-500/30 hover:text-emerald-200 sm:w-auto"
              >
                <SlidersHorizontal className="h-4 w-4" />
                Reset checklist
              </button>
            </div>

            <div className="mb-5 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
              <div className="mb-2 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <span className="text-sm font-bold uppercase tracking-wider text-slate-300">
                  Completion
                </span>
                <span className="font-mono text-sm text-emerald-300">
                  {checkedCount}/{checklistItems.length} ({completionPercent}%)
                </span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-emerald-400 transition-all duration-300"
                  style={{ width: `${completionPercent}%` }}
                />
              </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              {SECURE_MCP_MINIMUM_BAR.map((group) => (
                <div key={group.title} className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <h3 className="mb-3 flex items-center gap-2 text-base font-bold text-emerald-200">
                    <Wrench className="h-4 w-4 shrink-0" />
                    <span className="min-w-0 break-words">{group.title}</span>
                  </h3>
                  <ul className="space-y-2">
                    {group.items.map((item) => (
                      <li key={item}>
                        <label className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 text-sm leading-relaxed transition-colors ${
                          checkedItems[item]
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100'
                            : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-emerald-500/30'
                        }`}>
                          <input
                            type="checkbox"
                            checked={Boolean(checkedItems[item])}
                            onChange={() => toggleChecklistItem(item)}
                            className="mt-1 h-4 w-4 shrink-0 rounded border-slate-600 bg-slate-950 text-emerald-400 focus:ring-emerald-400 focus:ring-offset-0"
                          />
                          <span className={checkedItems[item] ? 'line-through decoration-emerald-300/60' : ''}>
                            {item}
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default SecureMcpGuideView;

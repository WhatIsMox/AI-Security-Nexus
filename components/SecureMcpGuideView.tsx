import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  ExternalLink,
  FileText,
  ListChecks,
  Network,
  ShieldCheck,
} from 'lucide-react';
import {
  SECURE_MCP_GUIDE_META,
  SECURE_MCP_GUIDE_SECTIONS,
  SECURE_MCP_MINIMUM_BAR,
  SecureMcpGuideSection,
} from '../data_secure_mcp_guide';

const slugFromTitle = (title: string) =>
  title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

const ListBlock: React.FC<{ items: string[] }> = ({ items }) => (
  <ul className="space-y-2">
    {items.map((item, index) => (
      <li
        key={index}
        className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm leading-relaxed text-slate-300"
      >
        <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
        <span>{item}</span>
      </li>
    ))}
  </ul>
);

const GuideSection: React.FC<{ section: SecureMcpGuideSection }> = ({ section }) => (
  <section
    id={section.id}
    className="scroll-mt-8 rounded-xl border border-slate-800 bg-slate-900/70 p-5 md:p-6"
  >
    <div className="mb-4 flex items-start gap-3">
      <div className="mt-1 rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-2">
        <ShieldCheck className="h-4 w-4 text-cyan-300" />
      </div>
      <div>
        <h2 className="text-2xl font-bold text-white">{section.title}</h2>
        <div className="mt-2 h-px w-20 bg-cyan-400/40" />
      </div>
    </div>

    {section.body && (
      <div className="space-y-3 text-sm leading-relaxed text-slate-300 md:text-base">
        {section.body.map((paragraph, index) => (
          <p key={index}>{paragraph}</p>
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
        {section.subsections.map((subsection, index) => (
          <div key={index} className="rounded-lg border border-slate-800 bg-slate-950/40 p-4">
            <h3 className="mb-2 text-base font-bold text-slate-100">{subsection.title}</h3>
            {subsection.body && (
              <div className="space-y-2 text-sm leading-relaxed text-slate-400">
                {subsection.body.map((paragraph, paragraphIndex) => (
                  <p key={paragraphIndex}>{paragraph}</p>
                ))}
              </div>
            )}
            {subsection.bullets && (
              <div className={subsection.body ? 'mt-3' : ''}>
                <ListBlock items={subsection.bullets} />
              </div>
            )}
          </div>
        ))}
      </div>
    )}
  </section>
);

const SecureMcpGuideView: React.FC = () => {
  const meta = SECURE_MCP_GUIDE_META;
  const checklistItems = useMemo(
    () => SECURE_MCP_MINIMUM_BAR.flatMap((group) => group.items),
    []
  );
  const [checkedItems, setCheckedItems] = useState<Record<string, boolean>>({});
  const tocItems = useMemo(() => meta.tableOfContents.map((item) => {
    const targetId =
      item === "MCP Security Minimum Bar (Review Checklist)"
          ? 'minimum-bar'
          : slugFromTitle(item.replace(/^\d+\.\s*/, ''));
    return { label: item, targetId };
  }), [meta.tableOfContents]);
  const [activeSectionId, setActiveSectionId] = useState(tocItems[0]?.targetId || '');

  useEffect(() => {
    const sectionElements = tocItems
      .map((item) => document.getElementById(item.targetId))
      .filter((element): element is HTMLElement => Boolean(element));

    if (sectionElements.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visibleEntries = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);

        if (visibleEntries[0]?.target.id) {
          setActiveSectionId(visibleEntries[0].target.id);
        }
      },
      {
        root: null,
        rootMargin: '-20% 0px -55% 0px',
        threshold: [0.1, 0.25, 0.5, 0.75]
      }
    );

    sectionElements.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, [tocItems]);

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

  return (
    <div className="mx-auto max-w-7xl animate-in fade-in duration-500 p-4 md:p-8">
      <div className="mb-8 rounded-2xl border border-cyan-500/20 bg-slate-900/70 p-6 md:p-8">
        <div className="mb-5 flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-bold uppercase tracking-wider text-cyan-300">
            <Network className="h-3.5 w-3.5" />
            Secure MCP Development
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {meta.version}
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-3 py-1 text-xs font-mono text-slate-400">
            {meta.publicationDate}
          </span>
        </div>

        <h1 className="max-w-4xl text-3xl font-bold text-white md:text-5xl">
          {meta.title}
        </h1>
        <p className="mt-4 max-w-3xl text-sm leading-relaxed text-slate-400 md:text-base">
          Practical security controls for MCP server architecture, tool design, validation,
          prompt-injection defenses, identity, deployment, governance, and continuous validation.
        </p>

        <div className="mt-6 grid gap-4 lg:grid-cols-[1.35fr_0.65fr]">
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-amber-300">
              <AlertTriangle className="h-4 w-4" />
              Notice
            </div>
            <p className="text-sm leading-relaxed text-slate-300">{meta.disclaimer}</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <BookOpen className="h-4 w-4 text-cyan-300" />
              Source
            </div>
            <div className="space-y-1 text-sm text-slate-400">
              <a
                href={meta.resourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200"
              >
                {meta.site}
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
              <a
                href={meta.license.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200"
              >
                {meta.license.name}
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-8 lg:grid-cols-[280px_1fr]">
        <aside className="lg:sticky lg:top-8 lg:self-start">
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-300">
              <FileText className="h-4 w-4 text-cyan-300" />
              Table of Contents
            </div>
            <nav className="space-y-1">
              {tocItems.map((item) => {
                const isActive = activeSectionId === item.targetId;
                return (
                  <a
                    key={item.label}
                    href={`#${item.targetId}`}
                    className={`block rounded-md border px-3 py-2 text-sm transition-colors ${
                      isActive
                        ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                        : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    {item.label}
                  </a>
                );
              })}
            </nav>
          </div>
        </aside>

        <div className="space-y-6">
          {SECURE_MCP_GUIDE_SECTIONS.map((section) => (
            <GuideSection key={section.id} section={section} />
          ))}

          <section
            id="minimum-bar"
            className="scroll-mt-8 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5 md:p-6"
          >
            <div className="mb-5 flex items-center gap-3">
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-2">
                <ListChecks className="h-5 w-5 text-emerald-300" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">
                  MCP Security Minimum Bar
                </h2>
                <p className="text-sm text-slate-400">Review checklist</p>
              </div>
            </div>

            <div className="mb-5 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
              <div className="mb-2 flex items-center justify-between gap-4">
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
                  <h3 className="mb-3 text-base font-bold text-emerald-200">{group.title}</h3>
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

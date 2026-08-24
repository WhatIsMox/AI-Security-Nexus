
import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { Pillar, TestItem, OwaspTop10Entry } from '../types';
import {
  Activity, AlertTriangle, ArrowRight,
  BookOpen, Bot, Brain, Bug, CheckCircle2, ChevronLeft, ChevronRight,
  Cpu, Crosshair, Database, ExternalLink, FileText, Flame, Gavel,
  Github, Globe, Layers, Network, Radar, Server,
  Shield, Sparkles, Star, Terminal, Wrench, Zap, Play,
} from 'lucide-react';
import {
  TEST_DATA,
  OWASP_TOP_10_DATA,
  OWASP_ML_TOP_10_DATA,
  OWASP_AGENTIC_APPLICATIONS_DATA,
  OWASP_AGENTIC_THREATS_DATA,
  OWASP_SAIF_THREATS_DATA,
  OWASP_MCP_TOP_10_DATA,
  SECURE_MCP_GUIDE_META,
  SECURE_MCP_GUIDE_SECTIONS,
  GENAI_DATA_SECURITY_META,
  GENAI_DATA_SECURITY_RISKS,
} from '../data';
import { TOOLS_BY_THREAT_ID } from '../tools_catalog';
import { INCIDENTS_BY_THREAT_ID } from '../incidents_catalog';

type PillarKey = Pillar | 'ALL' | 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'SAIFTOP10' | 'MCPTOP10' | 'SECUREMCPGUIDE' | 'GENAIDATASECURITY';

interface DashboardProps {
  onSelectPillar: (pillar: PillarKey) => void;
  onSelectThreatModel: () => void;
  onSelectTest: (test: TestItem) => void;
  onNavigateToOwasp: (id: string) => void;
  onSelectIncidents?: () => void;
  onSelectTools?: () => void;
}

/* ------------------------------------------------------------------ */
/*  Hooks & helpers                                                    */
/* ------------------------------------------------------------------ */

/** Observe an element and report once when it enters the viewport. */
function useInView<T extends HTMLElement>(threshold = 0.05): [React.RefObject<T>, boolean] {
  const ref = useRef<T>(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0) {
      setInView(true);
      return;
    }
    if (!('IntersectionObserver' in window)) {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setInView(true);
            observer.disconnect();
          }
        });
      },
      { threshold, rootMargin: '40px 0px 40px 0px' }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold]);
  return [ref, inView];
}

/** Animated counter that eases from 0 to `value` once visible. */
const CountUp: React.FC<{ value: number; duration?: number; className?: string; suffix?: string }> = ({
  value, duration = 800, className = '', suffix = '',
}) => {
  const [ref, inView] = useInView<HTMLSpanElement>(0.05);
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    if (!inView) return;
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(value * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, value, duration]);
  return (
    <span ref={ref} className={className}>
      {(inView ? display : value).toLocaleString()}{suffix}
    </span>
  );
};

/** Cycling typewriter line. */
const useTypewriter = (phrases: string[], typeMs = 45, holdMs = 2200) => {
  const [text, setText] = useState('');
  const [index, setIndex] = useState(0);
  const [deleting, setDeleting] = useState(false);
  useEffect(() => {
    const current = phrases[index % phrases.length];
    let timeout: ReturnType<typeof setTimeout>;
    if (!deleting && text === current) {
      timeout = setTimeout(() => setDeleting(true), holdMs);
    } else if (deleting && text === '') {
      setDeleting(false);
      setIndex((i) => (i + 1) % phrases.length);
    } else {
      timeout = setTimeout(
        () => setText(current.slice(0, text.length + (deleting ? -1 : 1))),
        deleting ? typeMs / 2 : typeMs
      );
    }
    return () => clearTimeout(timeout);
  }, [text, deleting, index, phrases, typeMs, holdMs]);
  return text;
};

/** Scroll-reveal: any `.reveal` element fades up when it enters the viewport. */
function useRevealObserver() {
  useEffect(() => {
    const els = Array.from(document.querySelectorAll<HTMLElement>('.reveal'));
    // Mark elements already in or near viewport as visible immediately
    els.forEach((el) => {
      const rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight + 100) {
        el.classList.add('is-visible');
      }
    });

    if (!('IntersectionObserver' in window)) {
      els.forEach((el) => el.classList.add('is-visible'));
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add('is-visible');
            observer.unobserve(e.target);
          }
        });
      },
      { threshold: 0.02, rootMargin: '60px 0px 60px 0px' }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);
}

/* ------------------------------------------------------------------ */
/*  Data aggregation (everything below is computed from real content)  */
/* ------------------------------------------------------------------ */

const RISK_META: Record<TestItem['riskLevel'], { label: string; text: string; bg: string; border: string; bar: string; rank: number }> = {
  Critical: { label: 'Critical', text: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30', bar: 'from-red-500 to-rose-400', rank: 4 },
  High: { label: 'High', text: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30', bar: 'from-orange-500 to-amber-400', rank: 3 },
  Medium: { label: 'Medium', text: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/30', bar: 'from-yellow-500 to-amber-300', rank: 2 },
  Low: { label: 'Low', text: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/30', bar: 'from-emerald-500 to-teal-400', rank: 1 },
};

const PILLAR_META: Record<Pillar, { name: string; blurb: string; icon: any; text: string; ring: string; iconBg: string; glow: string }> = {
  [Pillar.APP]: { name: 'Application', blurb: 'Orchestration, agents & plugins', icon: Layers, text: 'text-blue-400', ring: 'border-blue-500/40 hover:border-blue-400', iconBg: 'bg-blue-500/10 border-blue-500/30', glow: 'from-blue-500/20' },
  [Pillar.MODEL]: { name: 'AI Model', blurb: 'Inference, weights & fine-tuning', icon: Cpu, text: 'text-purple-400', ring: 'border-purple-500/40 hover:border-purple-400', iconBg: 'bg-purple-500/10 border-purple-500/30', glow: 'from-purple-500/20' },
  [Pillar.INFRA]: { name: 'Infrastructure', blurb: 'Supply chain & MLOps', icon: Server, text: 'text-amber-400', ring: 'border-amber-500/40 hover:border-amber-400', iconBg: 'bg-amber-500/10 border-amber-500/30', glow: 'from-amber-500/20' },
  [Pillar.DATA]: { name: 'Data', blurb: 'Training sets & RAG pipelines', icon: Database, text: 'text-emerald-400', ring: 'border-emerald-500/40 hover:border-emerald-400', iconBg: 'bg-emerald-500/10 border-emerald-500/30', glow: 'from-emerald-500/20' },
};

interface FrameworkCard {
  key: 'TOP10' | 'MLTOP10' | 'AGENTTOP10' | 'MCPTOP10' | 'SAIFTOP10' | 'GENAIDATASECURITY' | 'SECUREMCPGUIDE';
  name: string;
  edition: string;
  kind: string;
  blurb: string;
  icon: any;
  count: number;
  countLabel: string;
  previewId: string;
  previewTitle: string;
  // literal Tailwind class sets (JIT-safe)
  text: string;
  border: string;
  hoverBorder: string;
  iconBox: string;
  chipBg: string;
  glow: string;
  ring: string;
  arrowHover: string;
}

const buildFrameworkCards = (): FrameworkCard[] => [
  {
    key: 'TOP10',
    name: 'OWASP Top 10 for LLM Applications',
    edition: '2026 Edition',
    kind: 'Vulnerability Standard',
    blurb: 'The definitive industry benchmark for GenAI security—covering prompt injection, sensitive data leakage, vector database flaws, and over-privileged agents.',
    icon: Brain,
    count: OWASP_TOP_10_DATA.length,
    countLabel: 'threats',
    previewId: OWASP_TOP_10_DATA[0]?.id ?? '',
    previewTitle: OWASP_TOP_10_DATA[0]?.title ?? '',
    text: 'text-pink-400',
    border: 'border-pink-500/25',
    hoverBorder: 'hover:border-pink-400/70',
    iconBox: 'bg-pink-500/10 border-pink-500/30',
    chipBg: 'bg-pink-500/10 text-pink-300 border-pink-500/30',
    glow: 'bg-pink-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(236,72,153,0.35)]',
    arrowHover: 'group-hover:border-pink-500/60 group-hover:text-pink-300',
  },
  {
    key: 'AGENTTOP10',
    name: 'OWASP Agentic Top 10',
    edition: 'ASI & AST 2026',
    kind: 'Dual Framework',
    blurb: 'Autonomous agent security across two complementary layers: systemic application hazards (ASI01–ASI10) and compromised reusable tool skills (AST01–AST10).',
    icon: Bot,
    count: OWASP_AGENTIC_APPLICATIONS_DATA.length + OWASP_AGENTIC_THREATS_DATA.length,
    countLabel: 'threats',
    previewId: OWASP_AGENTIC_APPLICATIONS_DATA[0]?.id ?? '',
    previewTitle: OWASP_AGENTIC_APPLICATIONS_DATA[0]?.title ?? '',
    text: 'text-orange-400',
    border: 'border-orange-500/25',
    hoverBorder: 'hover:border-orange-400/70',
    iconBox: 'bg-orange-500/10 border-orange-500/30',
    chipBg: 'bg-orange-500/10 text-orange-300 border-orange-500/30',
    glow: 'bg-orange-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(249,115,22,0.35)]',
    arrowHover: 'group-hover:border-orange-500/60 group-hover:text-orange-300',
  },
  {
    key: 'MLTOP10',
    name: 'OWASP Machine Learning Top 10',
    edition: 'Classic ML & Deep Learning',
    kind: 'Threat Taxonomy',
    blurb: 'Core vulnerabilities in predictive AI and deep learning: adversarial evasion, training data poisoning, model extraction, and membership inference attacks.',
    icon: Cpu,
    count: OWASP_ML_TOP_10_DATA.length,
    countLabel: 'threats',
    previewId: OWASP_ML_TOP_10_DATA[0]?.id ?? '',
    previewTitle: OWASP_ML_TOP_10_DATA[0]?.title ?? '',
    text: 'text-emerald-400',
    border: 'border-emerald-500/25',
    hoverBorder: 'hover:border-emerald-400/70',
    iconBox: 'bg-emerald-500/10 border-emerald-500/30',
    chipBg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    glow: 'bg-emerald-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(16,185,129,0.35)]',
    arrowHover: 'group-hover:border-emerald-500/60 group-hover:text-emerald-300',
  },
  {
    key: 'MCPTOP10',
    name: 'OWASP MCP Top 10',
    edition: 'v0.1 Release',
    kind: 'Protocol Security',
    blurb: 'Emerging attack surfaces in Model Context Protocol stacks—addressing tool poisoning, rogue servers, confused-deputy authorization, and context leakage.',
    icon: Network,
    count: OWASP_MCP_TOP_10_DATA.length,
    countLabel: 'threats',
    previewId: OWASP_MCP_TOP_10_DATA[0]?.id ?? '',
    previewTitle: OWASP_MCP_TOP_10_DATA[0]?.title ?? '',
    text: 'text-cyan-400',
    border: 'border-cyan-500/25',
    hoverBorder: 'hover:border-cyan-400/70',
    iconBox: 'bg-cyan-500/10 border-cyan-500/30',
    chipBg: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
    glow: 'bg-cyan-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(34,211,238,0.35)]',
    arrowHover: 'group-hover:border-cyan-500/60 group-hover:text-cyan-300',
  },
  {
    key: 'SAIFTOP10',
    name: 'Google SAIF Risks',
    edition: 'Secure AI Framework',
    kind: 'Lifecycle Matrix',
    blurb: 'Google’s holistic risk model mapping 15 distinct threat vectors across dataset curation, model fine-tuning, inference infrastructure, and live operations.',
    icon: Gavel,
    count: OWASP_SAIF_THREATS_DATA.length,
    countLabel: 'risks',
    previewId: OWASP_SAIF_THREATS_DATA[0]?.id ?? '',
    previewTitle: OWASP_SAIF_THREATS_DATA[0]?.title ?? '',
    text: 'text-blue-400',
    border: 'border-blue-500/25',
    hoverBorder: 'hover:border-blue-400/70',
    iconBox: 'bg-blue-500/10 border-blue-500/30',
    chipBg: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
    glow: 'bg-blue-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(59,130,246,0.35)]',
    arrowHover: 'group-hover:border-blue-500/60 group-hover:text-blue-300',
  },
  {
    key: 'GENAIDATASECURITY',
    name: 'OWASP GenAI Data Security',
    edition: '2026 Guide',
    kind: 'Data Governance & DSPM',
    blurb: 'A 3-tiered data protection blueprint featuring 21 risk deep-dives and 13 AI-DSPM capabilities for governing enterprise training and inference data.',
    icon: Database,
    count: GENAI_DATA_SECURITY_RISKS.length,
    countLabel: 'risks',
    previewId: GENAI_DATA_SECURITY_RISKS[0]?.id ?? '',
    previewTitle: GENAI_DATA_SECURITY_RISKS[0]?.title ?? '',
    text: 'text-teal-400',
    border: 'border-teal-500/25',
    hoverBorder: 'hover:border-teal-400/70',
    iconBox: 'bg-teal-500/10 border-teal-500/30',
    chipBg: 'bg-teal-500/10 text-teal-300 border-teal-500/30',
    glow: 'bg-teal-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(45,212,191,0.35)]',
    arrowHover: 'group-hover:border-teal-500/60 group-hover:text-teal-300',
  },
  {
    key: 'SECUREMCPGUIDE',
    name: 'Secure MCP Server Development',
    edition: `Guide v${SECURE_MCP_GUIDE_META.version}`,
    kind: 'Engineering Blueprint',
    blurb: 'Concrete architectural controls and readiness checklist for building hardened, production-grade MCP servers that resist tool abuse and prompt injection.',
    icon: FileText,
    count: SECURE_MCP_GUIDE_SECTIONS.length,
    countLabel: 'sections',
    previewId: SECURE_MCP_GUIDE_SECTIONS[0]?.id ?? '',
    previewTitle: SECURE_MCP_GUIDE_SECTIONS[0]?.title ?? '',
    text: 'text-indigo-400',
    border: 'border-indigo-500/25',
    hoverBorder: 'hover:border-indigo-400/70',
    iconBox: 'bg-indigo-500/10 border-indigo-500/30',
    chipBg: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30',
    glow: 'bg-indigo-500/10',
    ring: 'group-hover:shadow-[0_0_40px_-8px_rgba(129,140,248,0.35)]',
    arrowHover: 'group-hover:border-indigo-500/60 group-hover:text-indigo-300',
  },
];

const Dashboard: React.FC<DashboardProps> = ({ 
  onSelectPillar, 
  onSelectThreatModel, 
  onSelectTest, 
  onNavigateToOwasp,
  onSelectIncidents,
  onSelectTools
}) => {
  useRevealObserver();

  /* ---------------- live aggregates ---------------- */
  const stats = useMemo(() => {
    const totalPayloads = TEST_DATA.reduce((acc, t) => acc + t.payloads.length, 0);
    const byRisk: Record<TestItem['riskLevel'], number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    TEST_DATA.forEach((t) => { byRisk[t.riskLevel] += 1; });

    const byPillar: Record<Pillar, TestItem[]> = { [Pillar.APP]: [], [Pillar.MODEL]: [], [Pillar.INFRA]: [], [Pillar.DATA]: [] };
    TEST_DATA.forEach((t) => byPillar[t.pillar].push(t));

    const tools = Object.values(TOOLS_BY_THREAT_ID).flat();
    const uniqueTools = Array.from(new Map(tools.map((t) => [t.name.toLowerCase(), t])).values());
    const toolCategories = {
      Offensive: uniqueTools.filter((t) => t.category === 'Offensive').length,
      Defensive: uniqueTools.filter((t) => t.category === 'Defensive').length,
      Both: uniqueTools.filter((t) => t.category === 'Both').length,
    };

    const incidents = Object.entries(INCIDENTS_BY_THREAT_ID).flatMap(([threatId, list]) =>
      list.map((r) => ({ threatId, title: r.title, url: r.url }))
    );

    const threatEntries = OWASP_TOP_10_DATA.length + OWASP_ML_TOP_10_DATA.length + OWASP_AGENTIC_APPLICATIONS_DATA.length + OWASP_AGENTIC_THREATS_DATA.length + OWASP_SAIF_THREATS_DATA.length + OWASP_MCP_TOP_10_DATA.length;

    const coverage = [
      { key: 'TOP10' as const, label: 'LLM Top 10', count: TEST_DATA.filter((t) => t.owaspTop10Ref).length },
      { key: 'MLTOP10' as const, label: 'ML Top 10', count: TEST_DATA.filter((t) => t.owaspMlTop10Ref).length },
      { key: 'AGENTTOP10' as const, label: 'Agentic', count: TEST_DATA.filter((t) => t.owaspAgenticRef).length },
      { key: 'SAIFTOP10' as const, label: 'SAIF', count: TEST_DATA.filter((t) => t.owaspSaifRef).length },
      { key: 'MCPTOP10' as const, label: 'MCP Top 10', count: TEST_DATA.filter((t) => t.owaspMcpTop10Ref).length },
    ];

    const spotlight = TEST_DATA.filter((t) => t.riskLevel === 'Critical' || t.riskLevel === 'High').sort(
      (a, b) => RISK_META[b.riskLevel].rank - RISK_META[a.riskLevel].rank || a.id.localeCompare(b.id)
    );

    return { totalPayloads, byRisk, byPillar, uniqueTools, toolCategories, incidents, threatEntries, coverage, spotlight, totalTests: TEST_DATA.length };
  }, []);

  const frameworks = useMemo(buildFrameworkCards, []);

  /* ---------------- hero typewriter ---------------- */
  const heroPhrases = useMemo(() => {
    const titles = [...OWASP_TOP_10_DATA, ...OWASP_AGENTIC_APPLICATIONS_DATA, ...OWASP_AGENTIC_THREATS_DATA, ...OWASP_MCP_TOP_10_DATA, ...OWASP_ML_TOP_10_DATA]
      .slice(0, 14)
      .map((e: OwaspTop10Entry) => e.title);
    return Array.from(new Set(titles));
  }, []);
  const typed = useTypewriter(heroPhrases);

  /* ---------------- featured test spotlight ---------------- */
  const [spotIndex, setSpotIndex] = useState(0);
  const [spotPaused, setSpotPaused] = useState(false);
  const featured = stats.spotlight[spotIndex % stats.spotlight.length];

  useEffect(() => {
    if (spotPaused || stats.spotlight.length === 0) return;
    const id = setInterval(() => setSpotIndex((i) => (i + 1) % stats.spotlight.length), 7000);
    return () => clearInterval(id);
  }, [spotPaused, stats.spotlight.length]);

  /* ---------------- incident spotlight ---------------- */
  const [incidentIndex, setIncidentIndex] = useState(0);
  useEffect(() => {
    if (stats.incidents.length === 0) return;
    const id = setInterval(() => setIncidentIndex((i) => (i + 1) % stats.incidents.length), 6000);
    return () => clearInterval(id);
  }, [stats.incidents.length]);

  /* ---------------- risk bar animation ---------------- */
  const [riskRef, riskInView] = useInView<HTMLDivElement>(0.3);

  const featuredCode = featured?.payloads.find((p) => p.code)?.code ?? featured?.payloads[0]?.code ?? '';

  const refsFor = useCallback((test: TestItem) => {
    const refs: { id: string; label: string }[] = [];
    if (test.owaspTop10Ref) refs.push({ id: test.owaspTop10Ref, label: 'LLM' });
    if (test.owaspMlTop10Ref) refs.push({ id: test.owaspMlTop10Ref, label: 'ML' });
    if (test.owaspAgenticRef) refs.push({ id: test.owaspAgenticRef, label: test.owaspAgenticRef.startsWith('AST') ? 'AST' : 'ASI' });
    if (test.owaspSaifRef) refs.push({ id: test.owaspSaifRef, label: 'SAIF' });
    if (test.owaspMcpTop10Ref) refs.push({ id: test.owaspMcpTop10Ref, label: 'MCP' });
    return refs;
  }, []);

  const incident = stats.incidents[incidentIndex % stats.incidents.length];

  return (
    <div className="container-fluid mx-auto max-w-7xl px-3 sm:px-4 md:px-8 pb-8">
      {/* ================================================================
          HERO
      ================================================================= */}
      <section className="relative overflow-hidden rounded-3xl border border-slate-800/80 bg-slate-900/40 mb-10">
        {/* animated backdrop */}
        <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
          <div className="absolute inset-0 bg-grid-animated opacity-60 [mask-image:radial-gradient(ellipse_70%_60%_at_50%_35%,black,transparent)]" />
          <div className="absolute -top-32 -left-24 w-[420px] h-[420px] rounded-full bg-cyan-500/15 blur-[110px] animate-aurora-a" />
          <div className="absolute top-10 right-0 w-[380px] h-[380px] rounded-full bg-purple-500/15 blur-[110px] animate-aurora-b" />
          <div className="absolute -bottom-40 left-1/3 w-[460px] h-[460px] rounded-full bg-pink-500/10 blur-[120px] animate-aurora-c" />
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-slate-950/60" />
        </div>

        <div className="relative z-10 px-4 py-10 sm:px-6 sm:py-14 md:px-14 md:py-20">
          <h1 className="text-3xl sm:text-4xl md:text-6xl font-extrabold tracking-tight text-white leading-[1.05] mb-6 animate-fade-up">
            Offensive testing & defense for{' '}
            <span className="relative inline-block">
              <span className="bg-gradient-to-r from-cyan-400 via-sky-400 to-purple-400 bg-clip-text text-transparent">
                modern AI systems
              </span>
              <span className="absolute -inset-x-2 bottom-1 h-3 bg-cyan-500/20 blur-lg -z-10" aria-hidden="true" />
            </span>
          </h1>

          <p className="max-w-2xl text-slate-400 text-base md:text-lg leading-relaxed mb-6 animate-fade-up [animation-delay:160ms]">
            The unified interactive intelligence hub for modern AI security.
            AI Security Nexus bridges the gap between static governance frameworks and real-world red teaming—empowering
            engineers, penetration testers, and security leaders to simulate adversarial threats, benchmark runtime
            guardrails, and audit agentic systems before vulnerabilities reach production.
          </p>

          {/* typewriter */}
          <div className="flex items-start sm:items-center gap-3 mb-9 min-h-7 animate-fade-up [animation-delay:240ms]">
            <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="min-w-0 break-words font-mono text-sm text-slate-300">
              <span className="text-slate-500">test defenses against </span>
              <span className="text-cyan-300 font-semibold">{typed}</span>
              <span className="text-cyan-400 animate-caret">▍</span>
            </span>
          </div>

          {/* CTA row */}
          <div className="flex flex-wrap items-center gap-3 mb-12 animate-fade-up [animation-delay:320ms]">
            <button
              onClick={() => onSelectPillar('ALL')}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-6 py-3 text-sm font-bold text-cyan-300 backdrop-blur transition-all hover:border-cyan-400 hover:bg-cyan-500/20 hover:-translate-y-0.5"
            >
              <Terminal className="w-4 h-4 text-cyan-400" />
              Explore {stats.totalTests} Test Cases
            </button>
            <button
              onClick={onSelectThreatModel}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/70 px-6 py-3 text-sm font-bold text-slate-200 backdrop-blur transition-all hover:border-slate-500 hover:bg-slate-800 hover:-translate-y-0.5"
            >
              <Crosshair className="w-4 h-4 text-purple-400" />
              Interactive Threat Model
            </button>
          </div>

          {/* live stat band */}
          <div className="row g-3 animate-fade-up [animation-delay:400ms]">
            {[
              { 
                label: 'Test cases', 
                value: stats.totalTests, 
                icon: Bug, 
                tint: 'text-red-400 bg-red-400/10 border-red-400/20 group-hover:border-red-400/50',
                action: () => onSelectPillar('ALL'),
                tooltip: 'Explore all 42+ curated test cases'
              },
              { 
                label: 'Attack payloads', 
                value: stats.totalPayloads, 
                icon: Zap, 
                tint: 'text-amber-400 bg-amber-400/10 border-amber-400/20 group-hover:border-amber-400/50',
                action: () => onSelectPillar('ALL'),
                tooltip: 'Explore active attack vectors & red-team payloads'
              },
              { 
                label: 'Framework threats', 
                value: stats.threatEntries, 
                icon: AlertTriangle, 
                tint: 'text-orange-400 bg-orange-400/10 border-orange-400/20 group-hover:border-orange-400/50',
                action: onSelectThreatModel,
                tooltip: 'Explore interactive SVG threat model'
              },
              { 
                label: 'Security standards', 
                value: frameworks.length, 
                icon: Radar, 
                tint: 'text-purple-400 bg-purple-400/10 border-purple-400/20 group-hover:border-purple-400/50',
                action: () => {
                  document.getElementById('frameworks-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                },
                tooltip: 'View all 7 major AI security standards'
              },
              { 
                label: 'Curated tools', 
                value: stats.uniqueTools.length, 
                icon: Wrench, 
                tint: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20 group-hover:border-cyan-400/50',
                action: () => {
                  if (onSelectTools) onSelectTools();
                  else onSelectPillar('ALL');
                },
                tooltip: 'Explore security tools matrix & posture filters'
              },
              { 
                label: 'Real-world exploits', 
                value: stats.incidents.length, 
                icon: Globe, 
                tint: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20 group-hover:border-emerald-400/50',
                action: () => {
                  if (onSelectIncidents) onSelectIncidents();
                  else onSelectPillar('ALL');
                },
                tooltip: 'Explore verified AI security incidents & CVE disclosures'
              },
            ].map((s) => (
              <div key={s.label} className="col-6 col-sm-4 col-lg-2 flex">
                <button
                  type="button"
                  onClick={s.action}
                  title={s.tooltip}
                  aria-label={`${s.label}: ${s.value}. Click to open dedicated view.`}
                  className="w-full text-left rounded-2xl border border-slate-800/80 bg-slate-950/50 backdrop-blur px-3 sm:px-4 py-4 transition-all duration-200 hover:border-slate-600 hover:bg-slate-900/80 hover:-translate-y-1 hover:shadow-lg group cursor-pointer flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className={`inline-flex p-2 rounded-lg border transition-colors ${s.tint}`}>
                        <s.icon className="w-4 h-4" />
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-300 group-hover:translate-x-0.5 transition-all" />
                    </div>
                    <div className="text-2xl font-extrabold text-white tabular-nums leading-none">
                      <CountUp value={s.value} />
                    </div>
                  </div>
                  <div className="mt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500 group-hover:text-slate-300 transition-colors">
                    {s.label}
                  </div>
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ================================================================
          FRAMEWORK EXPLORER
      ================================================================= */}
      <section id="frameworks-section" className="mb-16">
        <SectionHeader
          kicker="Security standards"
          title="All major AI security frameworks in one place"
          blurb="Navigate official vulnerability catalogs, threat taxonomies, and hardening guides side by side—with cross-references to live test cases, recommended tools, and real breaches."
        />
        <div className="row g-4">
          {frameworks.map((f, i) => (
            <div key={f.key} className="col-12 col-md-6 col-xl-4 flex">
              <button
              onClick={() => onSelectPillar(f.key)}
              className={`reveal group relative h-full w-full overflow-hidden rounded-2xl border ${f.border} ${f.hoverBorder} bg-slate-900/60 backdrop-blur p-5 sm:p-6 text-left transition-all duration-300 hover:-translate-y-1 ${f.ring}`}
              style={{ transitionDelay: `${(i % 3) * 70}ms` }}
            >
              {/* corner glow */}
              <div className={`absolute -top-16 -right-16 w-40 h-40 rounded-full ${f.glow} blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none`} />

              <div className="flex items-start justify-between gap-3 mb-4">
                <div className={`inline-flex p-3 rounded-xl border ${f.iconBox}`}>
                  <f.icon className={`w-6 h-6 ${f.text}`} />
                </div>
                <span className={`rounded-full border px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider ${f.chipBg}`}>
                  {f.count} {f.countLabel.toUpperCase()}
                </span>
              </div>

              <h3 className="text-base font-bold text-white leading-snug mb-1.5">{f.name}</h3>
              <p className="text-[11px] font-mono uppercase tracking-wider text-slate-500 mb-2.5">{f.edition} · {f.kind}</p>
              <p className="text-sm text-slate-400 leading-relaxed mb-4">{f.blurb}</p>

              <div className="mt-auto flex items-center justify-between border-t border-slate-800 pt-4">
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-0.5">Threat preview</p>
                  <p className="truncate font-mono text-xs text-slate-300">
                    <span className={`${f.text} font-bold`}>{f.previewId}</span> — {f.previewTitle}
                  </p>
                </div>
                <span className={`shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-full border border-slate-700 text-slate-400 transition-all group-hover:bg-slate-800/80 group-hover:translate-x-0.5 ${f.arrowHover}`}>
                  <ArrowRight className="w-4 h-4" />
                </span>
              </div>
              </button>
            </div>
          ))}

          {/* threat modelling card (special) */}
          <div className="col-12 col-md-6 col-xl-4 flex">
            <button
              onClick={onSelectThreatModel}
              className="reveal group relative h-full w-full overflow-hidden rounded-2xl border border-slate-700 bg-gradient-to-br from-slate-900 to-slate-950 p-5 sm:p-6 text-left transition-all duration-300 hover:-translate-y-1 hover:border-cyan-400/60 hover:shadow-[0_0_40px_-8px_rgba(34,211,238,0.3)]"
            >
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_10%,rgba(34,211,238,0.12),transparent_60%)] pointer-events-none" />
            <div className="flex items-start justify-between gap-3 mb-4">
              <div className="inline-flex p-3 rounded-xl border border-cyan-500/30 bg-cyan-500/10">
                <Crosshair className="w-6 h-6 text-cyan-400" />
              </div>
              <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider text-cyan-300">
                INTERACTIVE
              </span>
            </div>
            <h3 className="text-base font-bold text-white mb-1.5">AI Threat Modeling Pipeline</h3>
            <p className="text-[11px] font-mono uppercase tracking-wider text-slate-500 mb-2.5">SAIF Architecture & Risk Flow</p>
            <p className="text-sm text-slate-400 leading-relaxed mb-4">
              Explore an interactive AI pipeline diagram. Trace where threats enter the system, where they manifest, and how to apply controls across 24 core components.
            </p>
            <div className="mt-auto flex items-center justify-between border-t border-slate-800 pt-4">
              <p className="font-mono text-xs text-cyan-300">15 risks · 24 components</p>
              <span className="inline-flex items-center justify-center w-8 h-8 rounded-full border border-slate-700 text-slate-400 group-hover:border-cyan-400/60 group-hover:text-cyan-300 group-hover:translate-x-0.5 transition-all">
                <ArrowRight className="w-4 h-4" />
              </span>
            </div>
            </button>
          </div>
        </div>
      </section>

      {/* ================================================================
          AI SYSTEM ARCHITECTURE
      ================================================================= */}
      <section className="mb-16">
        <SectionHeader
          kicker="Four Pillars"
          title="Explore defenses across every architectural layer"
          blurb="AI systems fail in layers. A robust security strategy examines how vulnerabilities move between user interfaces, agent reasoning, model weights, RAG knowledge bases, and underlying infrastructure."
        />
        <div className="reveal relative rounded-3xl border border-slate-800/80 bg-slate-900/30 p-5 md:p-8 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(56,189,248,0.08),transparent_52%)] pointer-events-none" />
          <div className="absolute inset-0 opacity-[0.035] bg-[linear-gradient(rgba(148,163,184,0.7)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.7)_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />

          <div className="relative space-y-3">
            <ArchitectureBand
              index="01"
              title="Application & Agent Layer"
              description="User interfaces, autonomous agents, plugin orchestration, and API gateways where prompts enter the system"
            >
              <PillarNode
                pillar={Pillar.APP}
                tests={stats.byPillar[Pillar.APP]}
                onOpen={() => onSelectPillar(Pillar.APP)}
              />
            </ArchitectureBand>

            <div className="ml-0 lg:ml-[230px] h-5 flex items-center justify-center" aria-hidden="true">
              <span className="h-full w-px bg-gradient-to-b from-blue-400/50 to-purple-400/50" />
            </div>

            <ArchitectureBand
              index="02"
              title="Model & Knowledge Layer"
              description="Model inference checkpoints, weights, embeddings, RAG vector databases, and curated training data"
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <PillarNode
                  pillar={Pillar.MODEL}
                  tests={stats.byPillar[Pillar.MODEL]}
                  onOpen={() => onSelectPillar(Pillar.MODEL)}
                />
                <PillarNode
                  pillar={Pillar.DATA}
                  tests={stats.byPillar[Pillar.DATA]}
                  onOpen={() => onSelectPillar(Pillar.DATA)}
                />
              </div>
            </ArchitectureBand>

            <div className="ml-0 lg:ml-[230px] h-5 flex items-center justify-center" aria-hidden="true">
              <span className="h-full w-px bg-gradient-to-b from-purple-400/50 to-amber-400/50" />
            </div>

            <ArchitectureBand
              index="03"
              title="Infrastructure & Runtime Layer"
              description="Cloud execution environments, container registries, MLOps CI/CD pipelines, and third-party dependencies"
            >
              <PillarNode
                pillar={Pillar.INFRA}
                tests={stats.byPillar[Pillar.INFRA]}
                onOpen={() => onSelectPillar(Pillar.INFRA)}
              />
            </ArchitectureBand>
          </div>
        </div>
      </section>

      {/* ================================================================
          RISK POSTURE + COVERAGE
      ================================================================= */}
      <section className="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-16">
        {/* risk distribution */}
        <div ref={riskRef} className="reveal lg:col-span-3 rounded-3xl border border-slate-800/80 bg-slate-900/40 p-4 sm:p-6 md:p-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
            <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-red-400 shrink-0" />
              Test severity breakdown
            </h3>
            <button
              onClick={() => onSelectPillar('ALL')}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 self-start sm:self-auto cursor-pointer"
            >
              View all {stats.totalTests} tests <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <p className="text-xs sm:text-sm text-slate-500 mb-5 sm:mb-6">Distribution of verified test procedures organized by severity rating and potential blast radius.</p>

          <div className="space-y-4 sm:space-y-5">
            {(Object.keys(RISK_META) as TestItem['riskLevel'][]).map((level) => {
              const meta = RISK_META[level];
              const count = stats.byRisk[level];
              const pct = stats.totalTests ? (count / stats.totalTests) * 100 : 0;
              return (
                <div key={level} className="group cursor-pointer" onClick={() => onSelectPillar('ALL')}>
                  <div className="flex items-baseline justify-between mb-1.5">
                    <span className={`text-xs sm:text-sm font-bold ${meta.text}`}>{meta.label}</span>
                    <span className="text-[11px] sm:text-xs text-slate-500 font-mono tabular-nums">
                      {count} test cases · {pct.toFixed(0)}%
                    </span>
                  </div>
                  <div className="h-2.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full bg-gradient-to-r ${meta.bar} transition-all duration-[1200ms] ease-out shadow-[0_0_12px_rgba(255,255,255,0.15)]`}
                      style={{ width: riskInView ? `${Math.max(pct, 2)}%` : '0%' }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-6 sm:mt-7 rounded-2xl border border-slate-800 bg-slate-950/60 p-3.5 sm:p-4 flex items-start sm:items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 shrink-0 mt-0.5 sm:mt-0">
              <Flame className="w-4 h-4 text-red-400" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              <span className="font-bold text-red-300">{stats.byRisk.Critical + stats.byRisk.High} of {stats.totalTests} test cases</span> carry Critical or High severity. We recommend prioritizing these high-impact attack vectors in your audits, or tracing them in the{' '}
              <button onClick={onSelectThreatModel} className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-2">threat model</button>.
            </p>
          </div>
        </div>

        {/* coverage matrix */}
        <div className="reveal lg:col-span-2 rounded-3xl border border-slate-800/80 bg-slate-900/40 p-4 sm:p-6 md:p-8 flex flex-col">
          <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2 mb-2">
            <Radar className="w-5 h-5 text-purple-400 shrink-0" />
            Framework cross-coverage
          </h3>
          <p className="text-xs sm:text-sm text-slate-500 mb-5 sm:mb-6">How our testing procedures map back to major industry security frameworks.</p>

          <div className="space-y-4 sm:space-y-5 flex-1">
            {stats.coverage.map((c, i) => {
              const pct = stats.totalTests ? (c.count / stats.totalTests) * 100 : 0;
              return (
                <button key={c.key} onClick={() => onSelectPillar(c.key)} className="w-full text-left group">
                  <div className="flex items-baseline justify-between mb-1.5">
                    <span className="text-xs sm:text-sm font-semibold text-slate-300 group-hover:text-white transition-colors truncate pr-2">{c.label}</span>
                    <span className="text-[11px] sm:text-xs text-slate-500 font-mono tabular-nums shrink-0">{c.count} mapped</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-purple-500 to-cyan-400 transition-all duration-[1200ms] ease-out"
                      style={{ width: riskInView ? `${Math.max(pct, 3)}%` : '0%', transitionDelay: `${i * 90}ms` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>

          <div className="mt-5 sm:mt-6 pt-4 sm:pt-5 border-t border-slate-800">
            <div className="flex items-center gap-2 text-[11px] sm:text-xs text-slate-500">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              Click any framework to jump directly to its complete threat catalog and test cases.
            </div>
          </div>
        </div>
      </section>

      {/* ================================================================
          FEATURED TEST SPOTLIGHT
      ================================================================= */}
      <section className="mb-16">
        <SectionHeader
          kicker="Featured test case"
          title="High-impact test procedures & attack payloads"
          blurb="Step-by-step testing workflows featuring realistic attack payloads, vulnerability indicators, and actionable remediation steps."
        />

        {featured && (
          <div
            className="reveal relative overflow-hidden rounded-3xl border border-slate-800 bg-slate-900/50 backdrop-blur"
            onMouseEnter={() => setSpotPaused(true)}
            onMouseLeave={() => setSpotPaused(false)}
          >
            <div className="absolute inset-0 bg-gradient-to-br from-red-500/[0.06] via-transparent to-purple-500/[0.06] pointer-events-none" />

            <div className="relative grid grid-cols-1 lg:grid-cols-2">
              {/* meta */}
              <div className="p-4 sm:p-6 md:p-9 flex flex-col">
                <div className="flex items-center justify-between gap-3 mb-4 sm:mb-5">
                  <span className="font-mono text-xs font-bold tracking-widest text-slate-500 bg-slate-950/70 border border-slate-800 rounded-lg px-2.5 py-1 sm:px-3 sm:py-1.5">
                    {featured.id}
                  </span>
                  {/* rotation controls */}
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => setSpotIndex((i) => (i - 1 + stats.spotlight.length) % stats.spotlight.length)}
                      aria-label="Previous test"
                      className="p-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-white hover:border-slate-600 transition-colors min-w-[32px] min-h-[32px] flex items-center justify-center"
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setSpotIndex((i) => (i + 1) % stats.spotlight.length)}
                      aria-label="Next test"
                      className="p-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-white hover:border-slate-600 transition-colors min-w-[32px] min-h-[32px] flex items-center justify-center"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-3 sm:mb-4">
                  <span className={`rounded-full border px-2.5 py-0.5 sm:py-1 text-[10px] sm:text-[11px] font-bold ${RISK_META[featured.riskLevel].bg} ${RISK_META[featured.riskLevel].text} ${RISK_META[featured.riskLevel].border}`}>
                    {RISK_META[featured.riskLevel].label}
                  </span>
                  <span className="rounded-full border border-slate-700 bg-slate-800/60 px-2.5 py-0.5 sm:py-1 text-[10px] sm:text-[11px] font-bold text-slate-300">
                    {featured.pillar}
                  </span>
                  {refsFor(featured).map((r) => (
                    <button
                      key={r.id}
                      onClick={() => onNavigateToOwasp(r.id)}
                      className="rounded-full border border-cyan-500/25 bg-cyan-500/10 px-2 py-0.5 sm:px-2.5 sm:py-1 font-mono text-[10px] sm:text-[11px] font-bold text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                      title={`Open threat ${r.id}`}
                    >
                      {r.id}
                    </button>
                  ))}
                </div>

                <h3 key={featured.id} className="text-xl sm:text-2xl md:text-3xl font-extrabold text-white leading-tight mb-2.5 sm:mb-3 animate-fade-up break-words">
                  {featured.title}
                </h3>
                <p className="text-xs sm:text-sm text-slate-400 leading-relaxed mb-4 sm:mb-5 flex-1">{featured.summary}</p>

                <div className="grid grid-cols-3 gap-2 sm:gap-3 mb-5 sm:mb-6">
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2.5 sm:p-3 text-center sm:text-left">
                    <div className="font-mono text-base sm:text-lg font-bold text-white tabular-nums">{featured.objectives.length}</div>
                    <div className="text-[9px] sm:text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Objectives</div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2.5 sm:p-3 text-center sm:text-left">
                    <div className="font-mono text-base sm:text-lg font-bold text-white tabular-nums">{featured.payloads.length}</div>
                    <div className="text-[9px] sm:text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Payloads</div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-2.5 sm:p-3 text-center sm:text-left">
                    <div className="font-mono text-base sm:text-lg font-bold text-white tabular-nums">{featured.mitigationStrategies.length}</div>
                    <div className="text-[9px] sm:text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Mitigations</div>
                  </div>
                </div>

                <button
                  onClick={() => onSelectTest(featured)}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-2.5 sm:px-5 sm:py-3 text-xs sm:text-sm font-bold text-red-300 hover:bg-red-500/20 hover:border-red-400 transition-all self-start w-full sm:w-auto"
                >
                  <Play className="w-4 h-4" />
                  View complete test case
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

              {/* payload code */}
              <div className="border-t lg:border-t-0 lg:border-l border-slate-800 bg-slate-950/70 p-4 sm:p-6 md:p-9 flex flex-col">
                <div className="flex items-center gap-2 mb-3 sm:mb-4">
                  <span className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-red-500/70" />
                  <span className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-amber-500/70" />
                  <span className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-emerald-500/70" />
                  <span className="ml-2 font-mono text-[10px] sm:text-[11px] text-slate-500 truncate">{featured.id.toLowerCase()}-payload.txt</span>
                </div>
                <div className="relative flex-1 rounded-xl border border-slate-800 bg-slate-950 p-3.5 sm:p-5 overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_90%_0%,rgba(239,68,68,0.08),transparent_50%)] pointer-events-none" />
                  <pre key={featured.id} className="relative whitespace-pre-wrap break-words font-mono text-xs sm:text-[13px] leading-relaxed text-emerald-300/90 animate-fade-up max-h-52 sm:max-h-none overflow-y-auto">
                    <span className="text-slate-600 select-none">$ </span>{featuredCode || '// No payload snippet — open the test for full detail.'}
                  </pre>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500 font-mono">For authorized testing and security research</span>
                  {/* dots */}
                  <div className="flex items-center gap-1.5">
                    {stats.spotlight.slice(0, 8).map((_, i) => (
                      <button
                        key={i}
                        onClick={() => setSpotIndex(i)}
                        aria-label={`Go to test ${i + 1}`}
                        className={`h-1.5 rounded-full transition-all ${i === spotIndex % stats.spotlight.length ? 'w-6 bg-red-400' : 'w-1.5 bg-slate-700 hover:bg-slate-500'}`}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* progress bar */}
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-slate-800">
              <div
                key={`prog-${spotIndex}-${spotPaused}`}
                className="h-full bg-gradient-to-r from-red-500 to-purple-500"
                style={{ animation: spotPaused ? 'none' : 'spotProgress 7s linear forwards', width: '0%' }}
              />
            </div>
          </div>
        )}
      </section>

      {/* ================================================================
          TOOL MARQUEE
      ================================================================= */}
      <section className="mb-16 overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-2">
          <SectionHeader
            kicker="Security tooling"
            title={`${stats.uniqueTools.length} curated offensive & defensive security tools`}
            blurb={`${stats.toolCategories.Offensive} offensive scanners · ${stats.toolCategories.Defensive} defensive guardrails · ${stats.toolCategories.Both} dual-purpose platforms mapped directly to specific threats.`}
          />
          {onSelectTools && (
            <button
              type="button"
              onClick={onSelectTools}
              className="shrink-0 mb-6 text-xs font-semibold text-purple-400 hover:text-purple-300 inline-flex items-center gap-1.5 self-start sm:self-auto cursor-pointer"
            >
              Browse all {stats.uniqueTools.length} tools <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        <div 
          onClick={onSelectTools}
          className={`reveal relative space-y-3 [mask-image:linear-gradient(to_right,transparent,black_8%,black_92%,transparent)] ${onSelectTools ? 'cursor-pointer' : ''}`}
        >
          <div className="flex overflow-hidden">
            <div className="flex shrink-0 animate-marquee hover:[animation-play-state:paused]">
              {[...stats.uniqueTools, ...stats.uniqueTools].map((tool, i) => (
                <ToolChip key={`${tool.name}-${i}`} name={tool.name} cost={tool.cost} category={tool.category} />
              ))}
            </div>
          </div>
          <div className="flex overflow-hidden">
            <div className="flex shrink-0 animate-marquee-reverse hover:[animation-play-state:paused]">
              {[...stats.uniqueTools.slice().reverse(), ...stats.uniqueTools.slice().reverse()].map((tool, i) => (
                <ToolChip key={`r-${tool.name}-${i}`} name={tool.name} cost={tool.cost} category={tool.category} />
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ================================================================
          INCIDENT RADAR
      ================================================================= */}
      <section className="mb-16">
        <SectionHeader
          kicker="Threat intelligence"
          title="Documented security incidents & research disclosures"
          blurb="Verified real-world breaches, CVE advisories, and academic exploit papers demonstrating how these threats occur in the wild."
        />
        {incident && (
          <div className="reveal relative overflow-hidden rounded-3xl border border-slate-800/80 bg-slate-900/40 p-6 md:p-8">
            <div className="absolute -right-20 -top-20 w-64 h-64 rounded-full bg-orange-500/10 blur-3xl pointer-events-none" />
            <div className="relative flex flex-col md:flex-row md:items-center gap-5">
              <div className="shrink-0 inline-flex items-center gap-2 rounded-full border border-orange-500/30 bg-orange-500/10 px-4 py-1.5 self-start md:self-center">
                <Globe className="w-4 h-4 text-orange-400" />
                <span className="font-mono text-[11px] font-bold tracking-wider text-orange-300 uppercase">Mapped to {incident.threatId}</span>
              </div>
              <p key={incidentIndex} className="flex-1 text-slate-200 font-medium leading-relaxed animate-fade-up text-base md:text-lg">
                {incident.title}
              </p>
              {onSelectIncidents ? (
                <button
                  type="button"
                  onClick={onSelectIncidents}
                  className="shrink-0 inline-flex items-center gap-2 rounded-xl border border-orange-500/40 bg-orange-500/10 px-5 py-2.5 text-sm font-bold text-orange-300 hover:bg-orange-500/20 hover:border-orange-400 hover:text-white transition-all cursor-pointer shadow-sm hover:shadow-[0_0_15px_rgba(249,115,22,0.25)]"
                >
                  Read Case Study
                  <ArrowRight className="w-4 h-4 text-orange-400" />
                </button>
              ) : (
                <a
                  href={incident.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="shrink-0 inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-5 py-2.5 text-sm font-bold text-slate-200 hover:border-orange-400/60 hover:text-white transition-all"
                >
                  Read Case Study
                  <ExternalLink className="w-4 h-4" />
                </a>
              )}
            </div>
            <div className="relative mt-5 flex items-center gap-1.5">
              {stats.incidents.slice(0, 10).map((_, i) => (
                <button
                  key={i}
                  onClick={() => setIncidentIndex(i)}
                  aria-label={`Incident ${i + 1}`}
                  className={`h-1 rounded-full transition-all ${i === incidentIndex % stats.incidents.length ? 'w-8 bg-orange-400' : 'w-4 bg-slate-700 hover:bg-slate-500'}`}
                />
              ))}
              <span className="ml-auto font-mono text-[10px] text-slate-600 uppercase tracking-wider">{stats.incidents.length} incidents indexed</span>
            </div>
          </div>
        )}
      </section>

      {/* ================================================================
          FOOTER
      ================================================================= */}
      <footer className="border-t border-slate-800 pt-8 flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-slate-400 text-sm">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-slate-900 rounded-lg border border-slate-800">
              <BookOpen className="w-4 h-4 text-cyan-400" />
            </div>
            <span>© {new Date().getFullYear()} AI Security Nexus</span>
          </div>
          <span className="text-slate-700">·</span>
          <span className="text-xs text-slate-500 font-medium inline-flex items-center gap-1.5 transition-colors hover:text-slate-300">
            Made with <span className="text-pink-400 inline-block text-xs" aria-label="love">❤️</span> by <span className="text-slate-300 font-semibold tracking-wide">Gabriele Mossino</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-3">
          <span className="hidden md:flex items-center gap-1.5 text-[11px] text-slate-600 font-mono uppercase tracking-wider">
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            Powered by OWASP · SAIF · MCP
          </span>
          <a
            href="https://github.com/WhatIsMox/AI-Security-Nexus"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors group"
          >
            <Github className="w-5 h-5 group-hover:scale-110 transition-transform" />
            <span className="text-sm font-medium">Source Code</span>
          </a>
          <a
            href="https://github.com/WhatIsMox/AI-Security-Nexus"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-1.5 bg-cyan-450/10 text-cyan-450 border border-cyan-450/20 rounded-full hover:bg-cyan-450/20 transition-all text-sm font-bold group"
          >
            <Star className="w-4 h-4 group-hover:fill-cyan-450 transition-all" />
            Star this Project
          </a>
        </div>
      </footer>
    </div>
  );
};

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

const SectionHeader: React.FC<{ kicker: string; title: string; blurb?: string }> = ({ kicker, title, blurb }) => (
  <div className="reveal mb-8 max-w-3xl">
    <p className="flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-[0.3em] text-cyan-400 mb-3">
      <span className="inline-block h-px w-8 bg-cyan-400/60" />
      {kicker}
    </p>
    <h2 className="text-2xl md:text-4xl font-extrabold text-white tracking-tight mb-3">{title}</h2>
    {blurb && <p className="text-sm md:text-base text-slate-400 leading-relaxed">{blurb}</p>}
  </div>
);

const ArchitectureBand: React.FC<{
  index: string;
  title: string;
  description: string;
  children: React.ReactNode;
}> = ({ index, title, description, children }) => (
  <div className="grid lg:grid-cols-[210px_minmax(0,1fr)] gap-3 sm:gap-4 lg:gap-5 items-stretch">
    <div className="rounded-2xl border border-slate-800/80 bg-slate-950/55 p-3.5 sm:p-4 lg:p-5 flex lg:flex-col items-start gap-3 sm:gap-4 lg:gap-2">
      <span className="inline-flex h-7 sm:h-8 min-w-7 sm:min-w-8 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-2 font-mono text-[10px] sm:text-[11px] font-bold text-cyan-300">
        {index}
      </span>
      <div>
        <h3 className="text-xs sm:text-sm font-bold text-slate-200">{title}</h3>
        <p className="mt-0.5 sm:mt-1 text-[11px] sm:text-xs leading-relaxed text-slate-500">{description}</p>
      </div>
    </div>
    <div>{children}</div>
  </div>
);

const PillarNode: React.FC<{ pillar: Pillar; tests: TestItem[]; onOpen: () => void }> = ({ pillar, tests, onOpen }) => {
  const meta = PILLAR_META[pillar];
  const criticals = tests.filter((t) => t.riskLevel === 'Critical' || t.riskLevel === 'High').length;
  const top = [...tests].sort((a, b) => RISK_META[b.riskLevel].rank - RISK_META[a.riskLevel].rank)[0];
  return (
    <button
      onClick={onOpen}
      className={`group relative w-full overflow-hidden rounded-2xl border ${meta.ring} bg-slate-900/80 backdrop-blur p-3.5 sm:p-5 text-left transition-all duration-300 hover:-translate-y-1 hover:bg-slate-900`}
    >
      <div className={`absolute inset-x-0 top-0 h-24 bg-gradient-to-b ${meta.glow} to-transparent opacity-40 group-hover:opacity-80 transition-opacity pointer-events-none`} />
      <div className="relative flex items-start gap-3 sm:gap-4">
        <div className={`p-2.5 sm:p-3 rounded-xl border ${meta.iconBg} shrink-0`}>
          <meta.icon className={`w-5 h-5 sm:w-6 sm:h-6 ${meta.text}`} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <h4 className="font-bold text-sm sm:text-base text-white truncate">{meta.name}</h4>
            <span className="font-mono text-xs font-bold text-slate-400 tabular-nums">{tests.length}</span>
          </div>
          <p className="text-[11px] sm:text-xs text-slate-500 mb-2 sm:mb-3">{meta.blurb}</p>
          <div className="flex items-center gap-2 mb-2 sm:mb-3">
            <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-400 transition-all duration-1000"
                style={{ width: tests.length ? `${(criticals / tests.length) * 100}%` : '0%' }}
              />
            </div>
            <span className="text-[9px] sm:text-[10px] font-mono text-red-300/80 shrink-0">{criticals} crit</span>
          </div>
          {top && (
            <div className="truncate rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-1.5 sm:px-3 sm:py-2 text-left">
              <span className={`font-mono text-[9px] sm:text-[10px] font-bold ${RISK_META[top.riskLevel].text}`}>{top.id}</span>
              <span className="text-[11px] sm:text-xs text-slate-400 ml-1.5 sm:ml-2 truncate inline-block max-w-[180px] sm:max-w-none align-bottom">{top.title}</span>
            </div>
          )}
        </div>
      </div>
    </button>
  );
};

const CATEGORY_DOT: Record<string, string> = {
  Offensive: 'bg-red-400',
  Defensive: 'bg-emerald-400',
  Both: 'bg-amber-400',
};

const ToolChip: React.FC<{ name: string; cost: string; category?: 'Offensive' | 'Defensive' | 'Both' }> = ({ name, cost, category }) => (
  <span className="inline-flex items-center gap-2 whitespace-nowrap rounded-full border border-slate-800 bg-slate-900/80 px-4 py-2 mr-3 text-sm text-slate-300 hover:border-cyan-500/40 hover:text-white transition-colors">
    <span className={`h-1.5 w-1.5 rounded-full ${category ? CATEGORY_DOT[category] : 'bg-slate-500'}`} />
    <span className="font-semibold">{name}</span>
    <span className="font-mono text-[10px] text-slate-500 border-l border-slate-800 pl-2">{cost}</span>
  </span>
);

export default Dashboard;

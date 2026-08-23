import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, CheckCircle2, AlertTriangle, XCircle, MinusCircle, 
  Download, FileText, Printer, RotateCcw, Filter, Search, 
  Layers, Box, Server, Database, ArrowRight, Save, Check
} from 'lucide-react';
import { TEST_DATA } from '../data';
import { Pillar, TestItem } from '../types';

export type AuditStatus = 'NOT_TESTED' | 'PASSED' | 'VULNERABLE' | 'MITIGATED' | 'NA';

export interface AuditRecord {
  status: AuditStatus;
  notes: string;
  updatedAt: string;
}

interface AuditChecklistViewProps {
  onSelectTest: (test: TestItem) => void;
  onNavigateToOwasp: (id: string) => void;
}

const STORAGE_KEY = 'ai_security_nexus_audit_state_v1';

const STATUS_CONFIG: Record<AuditStatus, { label: string; bg: string; text: string; border: string; icon: any }> = {
  NOT_TESTED: { label: 'Not Tested', bg: 'bg-slate-800/40', text: 'text-slate-400', border: 'border-slate-700', icon: MinusCircle },
  PASSED: { label: 'Passed', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', icon: CheckCircle2 },
  VULNERABLE: { label: 'Vulnerable', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', icon: AlertTriangle },
  MITIGATED: { label: 'Mitigated', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', icon: Shield },
  NA: { label: 'N/A', bg: 'bg-slate-900', text: 'text-slate-500', border: 'border-slate-800', icon: XCircle }
};

export const AuditChecklistView: React.FC<AuditChecklistViewProps> = ({ onSelectTest, onNavigateToOwasp }) => {
  const [records, setRecords] = useState<Record<string, AuditRecord>>({});
  const [selectedPillar, setSelectedPillar] = useState<Pillar | 'ALL'>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<AuditStatus | 'ALL'>('ALL');
  const [sortMethod, setSortMethod] = useState<'severity' | 'id'>('severity');
  const [searchQuery, setSearchQuery] = useState('');
  const [isCopied, setIsCopied] = useState(false);

  const getRiskWeight = (level: string) => {
    switch (level) {
      case 'Critical': return 4;
      case 'High': return 3;
      case 'Medium': return 2;
      default: return 1;
    }
  };

  // Load audit state from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        setRecords(JSON.parse(saved));
      }
    } catch {
      // Ignore storage errors
    }
  }, []);

  // Save audit state to localStorage
  const saveRecords = (newRecords: Record<string, AuditRecord>) => {
    setRecords(newRecords);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newRecords));
    } catch {
      // Ignore storage errors
    }
  };

  const handleStatusChange = (testId: string, status: AuditStatus) => {
    const existing = records[testId] || { status: 'NOT_TESTED', notes: '', updatedAt: '' };
    const updated: AuditRecord = {
      ...existing,
      status,
      updatedAt: new Date().toISOString()
    };
    saveRecords({ ...records, [testId]: updated });
  };

  const handleNotesChange = (testId: string, notes: string) => {
    const existing = records[testId] || { status: 'NOT_TESTED', notes: '', updatedAt: '' };
    const updated: AuditRecord = {
      ...existing,
      notes,
      updatedAt: new Date().toISOString()
    };
    saveRecords({ ...records, [testId]: updated });
  };

  const handleReset = () => {
    if (window.confirm('Are you sure you want to reset all audit statuses and notes? This cannot be undone.')) {
      saveRecords({});
    }
  };

  // Metrics computation
  const stats = useMemo(() => {
    const total = TEST_DATA.length;
    let passed = 0;
    let vulnerable = 0;
    let mitigated = 0;
    let na = 0;
    let notTested = 0;

    for (const test of TEST_DATA) {
      const status = records[test.id]?.status || 'NOT_TESTED';
      if (status === 'PASSED') passed++;
      else if (status === 'VULNERABLE') vulnerable++;
      else if (status === 'MITIGATED') mitigated++;
      else if (status === 'NA') na++;
      else notTested++;
    }

    const tested = passed + vulnerable + mitigated + na;
    const progressPercent = Math.round((tested / total) * 100);

    return { total, passed, vulnerable, mitigated, na, notTested, tested, progressPercent };
  }, [records]);

  // Filter & sort tests by Criticality (highest severity first)
  const sortedTests = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    const filtered = TEST_DATA.filter(test => {
      if (selectedPillar !== 'ALL' && test.pillar !== selectedPillar) return false;
      
      const status = records[test.id]?.status || 'NOT_TESTED';
      if (selectedStatus !== 'ALL' && status !== selectedStatus) return false;

      if (query) {
        const text = `${test.id} ${test.title} ${test.summary} ${records[test.id]?.notes || ''}`.toLowerCase();
        if (!text.includes(query)) return false;
      }

      return true;
    });

    return [...filtered].sort((a, b) => {
      if (sortMethod === 'severity') {
        const diff = getRiskWeight(b.riskLevel) - getRiskWeight(a.riskLevel);
        if (diff !== 0) return diff;
      }
      return a.id.localeCompare(b.id);
    });
  }, [selectedPillar, selectedStatus, searchQuery, records, sortMethod]);

  // Export JSON report (sorted by criticality)
  const exportJson = () => {
    const sortedExportTests = [...TEST_DATA].sort((a, b) => {
      const diff = getRiskWeight(b.riskLevel) - getRiskWeight(a.riskLevel);
      if (diff !== 0) return diff;
      return a.id.localeCompare(b.id);
    });

    const reportData = {
      title: "AI Security Nexus - Audit Assessment Report",
      generatedAt: new Date().toISOString(),
      metrics: stats,
      results: sortedExportTests.map(test => ({
        id: test.id,
        title: test.title,
        pillar: test.pillar,
        riskLevel: test.riskLevel,
        status: records[test.id]?.status || 'NOT_TESTED',
        notes: records[test.id]?.notes || '',
        updatedAt: records[test.id]?.updatedAt || null,
        owaspTop10Ref: test.owaspTop10Ref || null,
        owaspMlTop10Ref: test.owaspMlTop10Ref || null,
        owaspAgenticRef: test.owaspAgenticRef || null,
        owaspSaifRef: test.owaspSaifRef || null,
        owaspMcpTop10Ref: test.owaspMcpTop10Ref || null
      }))
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai-security-audit-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export Markdown report (sorted by criticality)
  const exportMarkdown = () => {
    const sortedExportTests = [...TEST_DATA].sort((a, b) => {
      const diff = getRiskWeight(b.riskLevel) - getRiskWeight(a.riskLevel);
      if (diff !== 0) return diff;
      return a.id.localeCompare(b.id);
    });

    let md = `# AI Security Assessment Report\n\n`;
    md += `**Date**: ${new Date().toLocaleDateString()}  \n`;
    md += `**Overall Progress**: ${stats.progressPercent}% (${stats.tested}/${stats.total} tests evaluated)  \n`;
    md += `**Findings Summary**: Passed: ${stats.passed} | Vulnerable: ${stats.vulnerable} | Mitigated: ${stats.mitigated} | N/A: ${stats.na}\n\n`;
    md += `## Detailed Assessment Matrix (Sorted by Criticality)\n\n`;
    md += `| Test ID | Title | Pillar | Risk | Status | Notes |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;

    for (const test of sortedExportTests) {
      const rec = records[test.id];
      const status = rec?.status || 'NOT_TESTED';
      const notes = (rec?.notes || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
      md += `| ${test.id} | ${test.title} | ${test.pillar} | ${test.riskLevel} | **${status}** | ${notes} |\n`;
    }

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai-security-assessment-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container-fluid p-3 sm:p-4 md:p-8 max-w-6xl mx-auto animate-in fade-in duration-500">
      {/* Header */}
      <div className="mb-8 border-b border-slate-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-cyan-300 text-xs font-mono mb-3">
            <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
            Interactive Audit Suite
          </div>
          <h2 className="text-2xl md:text-3xl font-bold text-white tracking-tight">AI Security Audit & Readiness Checklist</h2>
          <p className="text-slate-400 text-sm md:text-base mt-1">
            Conduct interactive readiness reviews, track remediation milestones, and export structured assessment reports in Markdown, JSON, or printable PDF.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 self-stretch sm:self-auto">
          <button
            onClick={exportMarkdown}
            className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 hover:text-white rounded-lg text-xs font-medium transition-all"
            title="Export as Markdown Assessment"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export MD</span>
          </button>
          <button
            onClick={exportJson}
            className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 hover:text-white rounded-lg text-xs font-medium transition-all"
            title="Export as JSON Data"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={() => window.print()}
            className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 hover:text-white rounded-lg text-xs font-medium transition-all"
            title="Print or Save as PDF"
          >
            <Printer className="w-3.5 h-3.5 text-purple-400" />
            <span>Print</span>
          </button>
          <button
            onClick={handleReset}
            className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/30 rounded-lg transition-all"
            title="Reset All Checklist Data"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Progress & Metrics Dashboard */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-slate-400 font-medium">Audit Progress</span>
          <div className="text-2xl font-bold text-white font-mono mt-1">{stats.progressPercent}%</div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-2">
            <div 
              className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full transition-all duration-500" 
              style={{ width: `${stats.progressPercent}%` }}
            />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-emerald-400 font-medium flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Passed
          </span>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{stats.passed}</div>
          <span className="text-[11px] text-slate-500">No vulnerabilities</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-red-400 font-medium flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Vulnerable
          </span>
          <div className="text-2xl font-bold text-red-400 font-mono mt-1">{stats.vulnerable}</div>
          <span className="text-[11px] text-slate-500">Requires remediation</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-blue-400 font-medium flex items-center gap-1">
            <Shield className="w-3 h-3" /> Mitigated
          </span>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-1">{stats.mitigated}</div>
          <span className="text-[11px] text-slate-500">Defenses active</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-slate-400 font-medium flex items-center gap-1">
            <MinusCircle className="w-3 h-3" /> Remaining
          </span>
          <div className="text-2xl font-bold text-slate-300 font-mono mt-1">{stats.notTested}</div>
          <span className="text-[11px] text-slate-500">Awaiting test</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-slate-500 font-medium flex items-center gap-1">
            <XCircle className="w-3 h-3" /> Not Applicable
          </span>
          <div className="text-2xl font-bold text-slate-500 font-mono mt-1">{stats.na}</div>
          <span className="text-[11px] text-slate-500">Out of scope</span>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-3.5 mb-6 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          {/* Search */}
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search checklist tests or findings..."
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 overflow-x-auto w-full sm:w-auto">
            <button
              onClick={() => setSelectedStatus('ALL')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${selectedStatus === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
            >
              All Statuses
            </button>
            {(['NOT_TESTED', 'VULNERABLE', 'PASSED', 'MITIGATED', 'NA'] as AuditStatus[]).map(st => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all whitespace-nowrap ${
                  selectedStatus === st ? `${STATUS_CONFIG[st].bg} ${STATUS_CONFIG[st].text} border ${STATUS_CONFIG[st].border}` : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {STATUS_CONFIG[st].label}
              </button>
            ))}
          </div>
        </div>

        {/* Pillar & Sort Controls */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2 border-t border-slate-800/50 text-xs">
          {/* Pillar Filter */}
          <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
            <span className="text-slate-500 text-[11px] font-mono uppercase mr-1">Pillar:</span>
            <button
              onClick={() => setSelectedPillar('ALL')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${selectedPillar === 'ALL' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            >
              All ({TEST_DATA.length})
            </button>
            {[Pillar.APP, Pillar.MODEL, Pillar.INFRA, Pillar.DATA].map(p => (
              <button
                key={p}
                onClick={() => setSelectedPillar(p)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all whitespace-nowrap ${
                  selectedPillar === p ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Sort Control */}
          <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-auto">
            <span className="text-slate-500 text-[11px] font-mono uppercase mr-1">Sort:</span>
            <button
              onClick={() => setSortMethod('severity')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                sortMethod === 'severity'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
              title="Sort by Criticality: Critical -> High -> Medium -> Low"
            >
              Criticality (High → Low)
            </button>
            <button
              onClick={() => setSortMethod('id')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                sortMethod === 'id'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
              title="Sort alphabetically by Test ID"
            >
              By ID
            </button>
          </div>
        </div>
      </div>

      {/* Checklist Table / List */}
      <div className="space-y-3">
        {sortedTests.length === 0 ? (
          <div className="py-12 text-center text-slate-500 bg-slate-900/30 border border-dashed border-slate-800 rounded-xl">
            <p className="text-sm">No test cases match the active filter criteria.</p>
          </div>
        ) : (
          sortedTests.map((test) => {
            const rec = records[test.id] || { status: 'NOT_TESTED', notes: '', updatedAt: '' };
            const statusConfig = STATUS_CONFIG[rec.status];

            return (
              <div 
                key={test.id}
                className="bg-slate-900/70 border border-slate-800 hover:border-slate-700/80 rounded-xl p-4 transition-all"
              >
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                  {/* Test Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-mono text-xs text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-900/60">
                        {test.id}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        {test.pillar}
                      </span>
                      <span className={`text-[11px] font-medium px-2 py-0.5 rounded-full border ${
                        test.riskLevel === 'Critical' ? 'text-red-400 bg-red-400/10 border-red-400/20' :
                        test.riskLevel === 'High' ? 'text-orange-400 bg-orange-400/10 border-orange-400/20' :
                        'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
                      }`}>
                        {test.riskLevel}
                      </span>
                    </div>

                    <button
                      onClick={() => onSelectTest(test)}
                      className="text-left font-semibold text-slate-200 hover:text-cyan-400 transition-colors text-base group flex items-center gap-1.5"
                    >
                      <span>{test.title}</span>
                      <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </button>
                    <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                      {test.summary}
                    </p>
                  </div>

                  {/* Status Toggle Buttons */}
                  <div className="flex flex-wrap items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 shrink-0">
                    {(['NOT_TESTED', 'PASSED', 'VULNERABLE', 'MITIGATED', 'NA'] as AuditStatus[]).map(st => {
                      const cfg = STATUS_CONFIG[st];
                      const active = rec.status === st;
                      const Icon = cfg.icon;

                      return (
                        <button
                          key={st}
                          onClick={() => handleStatusChange(test.id, st)}
                          type="button"
                          className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-all ${
                            active
                              ? `${cfg.bg} ${cfg.text} border ${cfg.border} shadow-sm`
                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                          }`}
                        >
                          <Icon className="w-3 h-3" />
                          <span>{cfg.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Finding / Tester Notes Input */}
                <div className="mt-3 pt-3 border-t border-slate-800/60">
                  <input
                    type="text"
                    value={rec.notes}
                    onChange={e => handleNotesChange(test.id, e.target.value)}
                    placeholder="Add audit notes, test evidence, tool outputs, or Jira/CVE ticket links..."
                    className="w-full px-3 py-1.5 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
export default AuditChecklistView;

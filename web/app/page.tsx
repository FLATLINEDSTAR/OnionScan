"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Shield,
  Activity,
  AlertTriangle,
  Server,
  Layers,
  Search,
  RefreshCw,
  PlusCircle,
  Clock,
  GitCompare,
  Key,
  ExternalLink,
  ChevronRight,
  Database,
  CheckCircle2,
  XCircle,
  Sliders,
  FileText,
  Network
} from "lucide-react";
import {
  api,
  ScanItem,
  ScanDetail,
  TargetItem,
  Finding,
  AssetItem,
  DiffResult,
  GraphResponse
} from "../lib/api";
import EvidenceGraph from "./components/EvidenceGraph";

type Tab = "scans" | "findings" | "assets" | "graph" | "diff" | "settings";

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<Tab>("scans");
  const [daemonHealthy, setDaemonHealthy] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<AssetItem[]>([]);

  // Selected details
  const [selectedScan, setSelectedScan] = useState<ScanDetail | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Filter states
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [analyzerFilter, setAnalyzerFilter] = useState("ALL");
  const [targetFilter, setTargetFilter] = useState("ALL");

  // New Scan Modal
  const [showScanModal, setShowScanModal] = useState(false);
  const [newScanTarget, setNewScanTarget] = useState("");
  const [newScanAsync, setNewScanAsync] = useState(false);
  const [newScanMaxPages, setNewScanMaxPages] = useState(10);
  const [newScanTimeout, setNewScanTimeout] = useState("10s");
  const [scanSubmitting, setScanSubmitting] = useState(false);

  // Diff states
  const [diffTarget, setDiffTarget] = useState("");
  const [diffOldScan, setDiffOldScan] = useState("");
  const [diffNewScan, setDiffNewScan] = useState("");
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);

  // Graph states
  const [graphTarget, setGraphTarget] = useState("");
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);

  // Settings states
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:8080");
  const [apiKey, setApiKey] = useState("");
  const [settingsMessage, setSettingsMessage] = useState<string | null>(null);

  // Initial load & connection check
  useEffect(() => {
    const cfg = api.getConfig();
    setApiUrl(cfg.baseUrl);
    setApiKey(cfg.apiKey);
    checkHealthAndLoadData();
  }, []);

  const checkHealthAndLoadData = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.health();
      setDaemonHealthy(true);
      await refreshAllData();
    } catch (err: any) {
      setDaemonHealthy(false);
      setError(err.message || "Failed to connect to OnionSec daemon");
    } finally {
      setLoading(false);
    }
  };

  const refreshAllData = async () => {
    try {
      const [tRes, sRes, fRes, aRes] = await Promise.all([
        api.listTargets().catch(() => ({ targets: [], total: 0 })),
        api.listScans().catch(() => ({ scans: [], total: 0 })),
        api.listFindings().catch(() => ({ findings: [], total: 0 })),
        api.listAssets().catch(() => ({ assets: [], total: 0 })),
      ]);
      setTargets(tRes.targets || []);
      setScans(sRes.scans || []);
      setFindings(fRes.findings || []);
      setAssets(aRes.assets || []);
    } catch (err: any) {
      console.error("Failed to load dashboard data:", err);
    }
  };

  // Trigger New Scan
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScanTarget.trim()) return;
    setScanSubmitting(true);
    setError(null);

    try {
      const res = await api.startScan({
        target: newScanTarget.trim(),
        async: newScanAsync,
        limits: {
          max_pages: Number(newScanMaxPages) || 10,
          page_timeout: newScanTimeout,
        },
      });
      setShowScanModal(false);
      setNewScanTarget("");
      await refreshAllData();
      if (!newScanAsync && res) {
        setSelectedScan(res);
      }
    } catch (err: any) {
      setError(`Scan start failed: ${err.message}`);
    } finally {
      setScanSubmitting(false);
    }
  };

  // Inspect Scan Detail
  const handleInspectScan = async (id: string) => {
    try {
      setLoading(true);
      const detail = await api.getScan(id);
      setSelectedScan(detail);
    } catch (err: any) {
      setError(`Failed to load scan details: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Run Diff
  const handleRunDiff = async () => {
    if (!diffTarget || !diffOldScan || !diffNewScan) return;
    setDiffLoading(true);
    setError(null);
    try {
      const result = await api.getDiff(diffTarget, diffOldScan, diffNewScan);
      setDiffResult(result);
    } catch (err: any) {
      setError(`Diff failed: ${err.message}`);
    } finally {
      setDiffLoading(false);
    }
  };

  // Load Evidence Graph
  const loadGraph = async (tgt: string) => {
    if (!tgt) return;
    setGraphLoading(true);
    setError(null);
    try {
      const res = await api.getGraph(tgt);
      setGraphData(res);
    } catch (err: any) {
      setError(`Failed to fetch evidence graph: ${err.message}`);
    } finally {
      setGraphLoading(false);
    }
  };

  // Save Settings
  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    api.setConfig(apiUrl, apiKey);
    setSettingsMessage("Settings saved. Testing connection...");
    try {
      await api.health();
      setDaemonHealthy(true);
      setSettingsMessage("Connection successful! Connected to OnionSec daemon.");
      await refreshAllData();
    } catch (err: any) {
      setDaemonHealthy(false);
      setSettingsMessage(`Failed to connect: ${err.message}`);
    }
  };

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (analyzerFilter !== "ALL" && f.analyzer !== analyzerFilter) return false;
      if (targetFilter !== "ALL" && f.target !== targetFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchId = f.id.toLowerCase().includes(q);
        const matchTarget = f.target.toLowerCase().includes(q);
        const matchEvidence = f.evidence?.some((e) =>
          e.description.toLowerCase().includes(q) || e.type.toLowerCase().includes(q)
        );
        if (!matchTitle && !matchId && !matchTarget && !matchEvidence) return false;
      }
      return true;
    });
  }, [findings, severityFilter, analyzerFilter, targetFilter, searchQuery]);

  // Unique analyzers for filtering
  const availableAnalyzers = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.analyzer) set.add(f.analyzer);
    });
    return Array.from(set);
  }, [findings]);

  // Overall statistics
  const stats = useMemo(() => {
    const totalScans = scans.length;
    const totalTargets = targets.length;
    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = findings.filter((f) => f.severity === "HIGH").length;
    const avgScore =
      scans.length > 0
        ? Math.round(scans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / scans.length)
        : 0;
    return { totalScans, totalTargets, criticalCount, highCount, avgScore };
  }, [scans, targets, findings]);

  const getRiskScoreBadge = (score: number) => {
    if (score >= 75) return <span className="badge badge-critical">{score} RISK</span>;
    if (score >= 50) return <span className="badge badge-high">{score} RISK</span>;
    if (score >= 25) return <span className="badge badge-medium">{score} RISK</span>;
    return <span className="badge badge-healthy">{score} RISK</span>;
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return <span className="badge badge-critical">CRITICAL</span>;
      case "HIGH":
        return <span className="badge badge-high">HIGH</span>;
      case "MEDIUM":
        return <span className="badge badge-medium">MEDIUM</span>;
      case "LOW":
        return <span className="badge badge-low">LOW</span>;
      default:
        return <span className="badge badge-info">{severity}</span>;
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      {/* Top Navbar */}
      <header
        style={{
          borderBottom: "1px solid var(--border-color)",
          backgroundColor: "var(--bg-secondary)",
          padding: "12px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <Shield style={{ color: "var(--accent-cyan)", width: 28, height: 28 }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: "1.125rem", letterSpacing: "-0.02em" }}>
              OnionSec <span style={{ color: "var(--accent-cyan)", fontSize: "0.875rem", fontWeight: 500 }}>Dashboard</span>
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Tor Hidden Service Security & Correlation
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: "flex", gap: "8px" }}>
          <button
            onClick={() => setActiveTab("scans")}
            className={`btn ${activeTab === "scans" ? "btn-primary" : "btn-secondary"}`}
          >
            <Activity size={16} /> Scans & Targets
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={`btn ${activeTab === "findings" ? "btn-primary" : "btn-secondary"}`}
          >
            <AlertTriangle size={16} /> Findings Explorer ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab("assets")}
            className={`btn ${activeTab === "assets" ? "btn-primary" : "btn-secondary"}`}
          >
            <Database size={16} /> Evidence Matrix ({assets.length})
          </button>
          <button
            onClick={() => {
              setActiveTab("graph");
              if (!graphTarget && targets.length > 0) {
                setGraphTarget(targets[0].target);
                loadGraph(targets[0].target);
              }
            }}
            className={`btn ${activeTab === "graph" ? "btn-primary" : "btn-secondary"}`}
          >
            <Network size={16} /> Evidence Graph
          </button>
          <button
            onClick={() => setActiveTab("diff")}
            className={`btn ${activeTab === "diff" ? "btn-primary" : "btn-secondary"}`}
          >
            <GitCompare size={16} /> Scan Diff
          </button>
          <button
            onClick={() => setActiveTab("settings")}
            className={`btn ${activeTab === "settings" ? "btn-primary" : "btn-secondary"}`}
          >
            <Sliders size={16} /> API Settings
          </button>
        </nav>

        {/* Header Right Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div
            onClick={() => setActiveTab("settings")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              cursor: "pointer",
              padding: "4px 10px",
              borderRadius: "9999px",
              fontSize: "0.75rem",
              backgroundColor: daemonHealthy
                ? "rgba(16, 185, 129, 0.1)"
                : "rgba(244, 63, 94, 0.1)",
              border: `1px solid ${
                daemonHealthy ? "rgba(16, 185, 129, 0.3)" : "rgba(244, 63, 94, 0.3)"
              }`,
              color: daemonHealthy ? "#34d399" : "#fb7185",
            }}
          >
            {daemonHealthy ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            {daemonHealthy ? "Daemon Online" : "Daemon Disconnected"}
          </div>

          <button
            onClick={() => setShowScanModal(true)}
            className="btn btn-primary"
            style={{ fontWeight: 600 }}
          >
            <PlusCircle size={16} /> New Scan
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ padding: "24px", maxWidth: "1400px", margin: "0 auto", width: "100%", flex: 1 }}>
        {error && (
          <div
            style={{
              padding: "12px 16px",
              backgroundColor: "rgba(244, 63, 94, 0.1)",
              border: "1px solid rgba(244, 63, 94, 0.4)",
              borderRadius: "6px",
              color: "#fb7185",
              marginBottom: "20px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
            <button
              onClick={() => setError(null)}
              style={{ background: "none", border: "none", color: "#fb7185", cursor: "pointer" }}
            >
              ✕
            </button>
          </div>
        )}

        {/* TAB 1: SCANS & TARGETS */}
        {activeTab === "scans" && (
          <div>
            {/* Stat Cards */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "16px",
                marginBottom: "24px",
              }}
            >
              <div className="card">
                <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "4px" }}>
                  Monitored Targets
                </div>
                <div style={{ fontSize: "2rem", fontWeight: 700 }}>{stats.totalTargets}</div>
              </div>
              <div className="card">
                <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "4px" }}>
                  Total Scans Performed
                </div>
                <div style={{ fontSize: "2rem", fontWeight: 700 }}>{stats.totalScans}</div>
              </div>
              <div className="card">
                <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "4px" }}>
                  Critical & High Findings
                </div>
                <div style={{ fontSize: "2rem", fontWeight: 700, color: "#fb7185" }}>
                  {stats.criticalCount + stats.highCount}
                </div>
              </div>
              <div className="card">
                <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "4px" }}>
                  Average Fleet Risk Score
                </div>
                <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-cyan)" }}>
                  {stats.avgScore} <span style={{ fontSize: "1rem", color: "var(--text-muted)" }}>/ 100</span>
                </div>
              </div>
            </div>

            {/* Target Breakdown */}
            {targets.length > 0 && (
              <div className="card" style={{ marginBottom: "24px" }}>
                <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "12px" }}>
                  Active Targets Overview
                </h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "12px" }}>
                  {targets.map((t) => (
                    <div
                      key={t.target}
                      style={{
                        padding: "12px",
                        backgroundColor: "var(--bg-secondary)",
                        borderRadius: "6px",
                        border: "1px solid var(--border-color)",
                      }}
                    >
                      <div className="mono" style={{ fontWeight: 600, fontSize: "0.875rem", color: "var(--accent-cyan)" }}>
                        {t.target}
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "8px", fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        <span>{t.scan_count} scan(s)</span>
                        <span>Latest Score: {getRiskScoreBadge(t.latest_risk_score)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recent Scans Table */}
            <div className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <h3 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Scan History</h3>
                <button onClick={refreshAllData} className="btn btn-secondary" style={{ padding: "6px 12px", fontSize: "0.75rem" }}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>

              {scans.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)" }}>
                  No scans recorded yet. Click "New Scan" to audit your first onion target.
                </div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.875rem" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
                        <th style={{ padding: "12px 16px" }}>Target</th>
                        <th style={{ padding: "12px 16px" }}>Scan ID</th>
                        <th style={{ padding: "12px 16px" }}>Risk Score</th>
                        <th style={{ padding: "12px 16px" }}>Findings</th>
                        <th style={{ padding: "12px 16px" }}>Pages Crawled</th>
                        <th style={{ padding: "12px 16px" }}>Date</th>
                        <th style={{ padding: "12px 16px", textAlign: "right" }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map((s) => (
                        <tr
                          key={s.id}
                          style={{
                            borderBottom: "1px solid var(--border-color)",
                            transition: "background-color 0.15s",
                          }}
                          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "var(--bg-card-hover)")}
                          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                        >
                          <td style={{ padding: "12px 16px" }} className="mono">
                            <span style={{ color: "var(--accent-cyan)" }}>{s.target}</span>
                          </td>
                          <td className="mono" style={{ padding: "12px 16px", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                            {s.id}
                          </td>
                          <td style={{ padding: "12px 16px" }}>{getRiskScoreBadge(s.risk_score)}</td>
                          <td style={{ padding: "12px 16px" }}>
                            <span className="badge badge-neutral">{s.findings_count} findings</span>
                          </td>
                          <td style={{ padding: "12px 16px", color: "var(--text-secondary)" }}>
                            {s.pages_seen || 1}
                          </td>
                          <td style={{ padding: "12px 16px", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                            {new Date(s.ended_at || s.started_at).toLocaleString()}
                          </td>
                          <td style={{ padding: "12px 16px", textAlign: "right" }}>
                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px" }}>
                              <button
                                onClick={() => {
                                  setGraphTarget(s.target);
                                  loadGraph(s.target);
                                  setActiveTab("graph");
                                }}
                                className="btn btn-secondary"
                                style={{ padding: "4px 8px", fontSize: "0.75rem" }}
                                title="View Evidence Graph"
                              >
                                <Network size={13} />
                              </button>
                              <button
                                onClick={() => handleInspectScan(s.id)}
                                className="btn btn-secondary"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                              >
                                Inspect <ChevronRight size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: FINDINGS EXPLORER */}
        {activeTab === "findings" && (
          <div>
            {/* Filter and Search Bar */}
            <div className="card" style={{ marginBottom: "20px" }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: "12px",
                  alignItems: "center",
                }}
              >
                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Search Findings
                  </label>
                  <input
                    type="text"
                    placeholder="Search by ID, title, evidence..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Severity
                  </label>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Analyzer
                  </label>
                  <select
                    value={analyzerFilter}
                    onChange={(e) => setAnalyzerFilter(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  >
                    <option value="ALL">All Analyzers</option>
                    {availableAnalyzers.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Target
                  </label>
                  <select
                    value={targetFilter}
                    onChange={(e) => setTargetFilter(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  >
                    <option value="ALL">All Targets</option>
                    {targets.map((t) => (
                      <option key={t.target} value={t.target}>
                        {t.target}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Findings List & Detail Grid */}
            <div style={{ display: "grid", gridTemplateColumns: selectedFinding ? "1fr 1fr" : "1fr", gap: "20px" }}>
              {/* Findings Cards */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div style={{ fontSize: "0.875rem", color: "var(--text-muted)" }}>
                    Showing {filteredFindings.length} of {findings.length} findings
                  </div>
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="card" style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)" }}>
                    No findings match the selected filters.
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    {filteredFindings.map((f, idx) => {
                      const isSelected = selectedFinding?.id === f.id && selectedFinding?.target === f.target;
                      return (
                        <div
                          key={`${f.id}-${f.target}-${idx}`}
                          onClick={() => setSelectedFinding(f)}
                          style={{
                            padding: "16px",
                            backgroundColor: isSelected ? "var(--bg-card-hover)" : "var(--bg-card)",
                            border: `1px solid ${isSelected ? "var(--accent-cyan)" : "var(--border-color)"}`,
                            borderRadius: "8px",
                            cursor: "pointer",
                            transition: "all 0.15s ease",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              {getSeverityBadge(f.severity)}
                              <span className="mono" style={{ fontWeight: 700, fontSize: "0.875rem" }}>
                                {f.id}
                              </span>
                              <span className="badge badge-neutral">{f.analyzer}</span>
                            </div>
                            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                              Conf: {Math.round(f.confidence * 100)}%
                            </div>
                          </div>

                          <div style={{ fontWeight: 600, fontSize: "0.95rem", marginBottom: "6px" }}>
                            {f.title}
                          </div>

                          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                            <span className="mono">{f.target}</span>
                            <span>{f.created_at ? new Date(f.created_at).toLocaleDateString() : ""}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Selected Finding Deep Inspection Panel */}
              {selectedFinding && (
                <div style={{ position: "sticky", top: "24px", height: "fit-content" }}>
                  <div className="card" style={{ border: "1px solid var(--accent-cyan)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px" }}>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                          {getSeverityBadge(selectedFinding.severity)}
                          <span className="mono" style={{ fontWeight: 700, fontSize: "1.125rem" }}>
                            {selectedFinding.id}
                          </span>
                        </div>
                        <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>{selectedFinding.title}</h2>
                      </div>
                      <button
                        onClick={() => setSelectedFinding(null)}
                        style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "1.25rem" }}
                      >
                        ✕
                      </button>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px", backgroundColor: "var(--bg-secondary)", padding: "12px", borderRadius: "6px" }}>
                      <div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Target</div>
                        <div className="mono" style={{ fontSize: "0.875rem", color: "var(--accent-cyan)" }}>
                          {selectedFinding.target}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Analyzer Rule</div>
                        <div style={{ fontSize: "0.875rem" }}>{selectedFinding.analyzer}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Confidence Score</div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "2px" }}>
                          <div style={{ flex: 1, height: "6px", backgroundColor: "var(--border-color)", borderRadius: "3px", overflow: "hidden" }}>
                            <div
                              style={{
                                width: `${Math.round(selectedFinding.confidence * 100)}%`,
                                height: "100%",
                                backgroundColor: "var(--accent-emerald)",
                              }}
                            />
                          </div>
                          <span style={{ fontSize: "0.75rem", fontWeight: 600 }}>
                            {Math.round(selectedFinding.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Discovered</div>
                        <div style={{ fontSize: "0.75rem" }}>
                          {selectedFinding.created_at ? new Date(selectedFinding.created_at).toLocaleString() : "N/A"}
                        </div>
                      </div>
                    </div>

                    {/* Evidence Section */}
                    <div style={{ marginBottom: "16px" }}>
                      <h4 style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "8px" }}>
                        Corroborating Evidence ({selectedFinding.evidence?.length || 0})
                      </h4>
                      {selectedFinding.evidence && selectedFinding.evidence.length > 0 ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {selectedFinding.evidence.map((ev, i) => (
                            <div
                              key={i}
                              style={{
                                padding: "10px",
                                backgroundColor: "var(--bg-secondary)",
                                border: "1px solid var(--border-color)",
                                borderRadius: "6px",
                                fontSize: "0.8125rem",
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                                <span className="badge badge-neutral" style={{ fontSize: "0.7rem" }}>
                                  {ev.type}
                                </span>
                                {ev.source && (
                                  <span className="mono" style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                                    {ev.source}
                                  </span>
                                )}
                              </div>
                              <div className="mono" style={{ wordBreak: "break-all", color: "var(--text-primary)" }}>
                                {ev.description}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>
                          No explicit evidence payloads attached to this finding.
                        </div>
                      )}
                    </div>

                    {/* Remediation section */}
                    <div
                      style={{
                        padding: "12px",
                        backgroundColor: "rgba(6, 182, 212, 0.08)",
                        border: "1px solid rgba(6, 182, 212, 0.2)",
                        borderRadius: "6px",
                      }}
                    >
                      <h4 style={{ fontSize: "0.8125rem", fontWeight: 600, color: "var(--accent-cyan)", marginBottom: "4px" }}>
                        Remediation Guidance
                      </h4>
                      <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
                        {selectedFinding.remediation ||
                          "Review service configuration, remove cleartext identifiers, and avoid linking clearnet infrastructure or leaked secrets with this onion hidden service."}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: EVIDENCE & ASSET MATRIX */}
        {activeTab === "assets" && (
          <div>
            <div className="card" style={{ marginBottom: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <h3 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Indexed Evidence & Co-occurrences</h3>
                  <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginTop: "4px" }}>
                    Bipartite asset store tracking shared IP addresses, TLS certificates, emails, and signatures across hidden services.
                  </p>
                </div>
                <button onClick={refreshAllData} className="btn btn-secondary" style={{ padding: "6px 12px", fontSize: "0.75rem" }}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>
            </div>

            {assets.length === 0 ? (
              <div className="card" style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)" }}>
                No assets indexed in SQLite yet. Perform a scan to automatically index evidence.
              </div>
            ) : (
              <div className="card" style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.875rem" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
                      <th style={{ padding: "12px 16px" }}>Asset Type</th>
                      <th style={{ padding: "12px 16px" }}>Canonical Value</th>
                      <th style={{ padding: "12px 16px" }}>Co-Occurring Onions</th>
                      <th style={{ padding: "12px 16px" }}>First Seen</th>
                      <th style={{ padding: "12px 16px" }}>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map((a, i) => {
                      const isMultiTarget = a.co_occurring_targets && a.co_occurring_targets.length > 1;
                      return (
                        <tr
                          key={i}
                          style={{
                            borderBottom: "1px solid var(--border-color)",
                            backgroundColor: isMultiTarget ? "rgba(244, 63, 94, 0.05)" : "transparent",
                          }}
                        >
                          <td style={{ padding: "12px 16px" }}>
                            <span className="badge badge-neutral">{a.type}</span>
                          </td>
                          <td style={{ padding: "12px 16px" }} className="mono">
                            <span style={{ color: isMultiTarget ? "#fb7185" : "var(--text-primary)" }}>
                              {a.canonical_value}
                            </span>
                          </td>
                          <td style={{ padding: "12px 16px" }}>
                            {a.co_occurring_targets && a.co_occurring_targets.length > 0 ? (
                              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                {a.co_occurring_targets.map((tgt, ti) => (
                                  <span
                                    key={ti}
                                    className={`badge ${isMultiTarget ? "badge-critical" : "badge-neutral"}`}
                                  >
                                    {tgt}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span style={{ color: "var(--text-muted)" }}>None</span>
                            )}
                          </td>
                          <td style={{ padding: "12px 16px", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                            {a.first_seen ? new Date(a.first_seen).toLocaleDateString() : "-"}
                          </td>
                          <td style={{ padding: "12px 16px", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                            {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "-"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: SCAN DIFF */}
        {activeTab === "diff" && (
          <div>
            <div className="card" style={{ marginBottom: "20px" }}>
              <h3 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "12px" }}>
                Compare Target Scans
              </h3>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: "12px",
                  alignItems: "flex-end",
                }}
              >
                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Select Target
                  </label>
                  <select
                    value={diffTarget}
                    onChange={(e) => {
                      setDiffTarget(e.target.value);
                      setDiffResult(null);
                    }}
                    className="input"
                    style={{ width: "100%" }}
                  >
                    <option value="">-- Choose target --</option>
                    {targets.map((t) => (
                      <option key={t.target} value={t.target}>
                        {t.target}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Old / Baseline Scan ID
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 20260910T120000Z"
                    value={diffOldScan}
                    onChange={(e) => setDiffOldScan(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    New / Current Scan ID
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 20260912T150000Z"
                    value={diffNewScan}
                    onChange={(e) => setDiffNewScan(e.target.value)}
                    className="input"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <button
                    onClick={handleRunDiff}
                    disabled={!diffTarget || !diffOldScan || !diffNewScan || diffLoading}
                    className="btn btn-primary"
                    style={{ width: "100%" }}
                  >
                    <GitCompare size={16} /> {diffLoading ? "Computing Diff..." : "Run Diff"}
                  </button>
                </div>
              </div>
            </div>

            {diffResult && (
              <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                {/* Diff Overview */}
                <div className="card">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: "0.875rem", color: "var(--text-muted)" }}>Target Diff</div>
                      <div className="mono" style={{ fontSize: "1.125rem", fontWeight: 600, color: "var(--accent-cyan)" }}>
                        {diffResult.target}
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: "0.875rem", color: "var(--text-muted)" }}>Risk Score Delta</div>
                      <div
                        style={{
                          fontSize: "1.5rem",
                          fontWeight: 700,
                          color: diffResult.risk_score_delta > 0 ? "#fb7185" : "#34d399",
                        }}
                      >
                        {diffResult.risk_score_delta > 0 ? `+${diffResult.risk_score_delta}` : diffResult.risk_score_delta}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Diff Columns */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "16px" }}>
                  {/* New Findings */}
                  <div className="card" style={{ borderTop: "3px solid #fb7185" }}>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#fb7185", marginBottom: "12px" }}>
                      New Findings ({diffResult.new_findings?.length || 0})
                    </h4>
                    {diffResult.new_findings && diffResult.new_findings.length > 0 ? (
                      diffResult.new_findings.map((f, i) => (
                        <div key={i} style={{ padding: "8px", backgroundColor: "var(--bg-secondary)", borderRadius: "4px", marginBottom: "8px" }}>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            {getSeverityBadge(f.severity)}
                            <span className="mono" style={{ fontWeight: 600, fontSize: "0.8rem" }}>{f.id}</span>
                          </div>
                          <div style={{ fontSize: "0.8rem", marginTop: "4px" }}>{f.title}</div>
                        </div>
                      ))
                    ) : (
                      <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>No new findings introduced.</div>
                    )}
                  </div>

                  {/* Resolved Findings */}
                  <div className="card" style={{ borderTop: "3px solid #34d399" }}>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#34d399", marginBottom: "12px" }}>
                      Resolved Findings ({diffResult.resolved_findings?.length || 0})
                    </h4>
                    {diffResult.resolved_findings && diffResult.resolved_findings.length > 0 ? (
                      diffResult.resolved_findings.map((f, i) => (
                        <div key={i} style={{ padding: "8px", backgroundColor: "var(--bg-secondary)", borderRadius: "4px", marginBottom: "8px" }}>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            {getSeverityBadge(f.severity)}
                            <span className="mono" style={{ fontWeight: 600, fontSize: "0.8rem" }}>{f.id}</span>
                          </div>
                          <div style={{ fontSize: "0.8rem", marginTop: "4px" }}>{f.title}</div>
                        </div>
                      ))
                    ) : (
                      <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>No resolved findings.</div>
                    )}
                  </div>

                  {/* Persisting Findings */}
                  <div className="card" style={{ borderTop: "3px solid var(--accent-cyan)" }}>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--accent-cyan)", marginBottom: "12px" }}>
                      Persisting Findings ({diffResult.persisting_findings?.length || 0})
                    </h4>
                    {diffResult.persisting_findings && diffResult.persisting_findings.length > 0 ? (
                      diffResult.persisting_findings.map((f, i) => (
                        <div key={i} style={{ padding: "8px", backgroundColor: "var(--bg-secondary)", borderRadius: "4px", marginBottom: "8px" }}>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            {getSeverityBadge(f.severity)}
                            <span className="mono" style={{ fontWeight: 600, fontSize: "0.8rem" }}>{f.id}</span>
                          </div>
                          <div style={{ fontSize: "0.8rem", marginTop: "4px" }}>{f.title}</div>
                        </div>
                      ))
                    ) : (
                      <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>No persisting findings.</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB: EVIDENCE GRAPH */}
        {activeTab === "graph" && (
          <div>
            <div className="card" style={{ marginBottom: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
                <div>
                  <h3 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Interactive Evidence Graph</h3>
                  <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginTop: "4px" }}>
                    Cytoscape.js visualization of bipartite evidence nodes and co-occurring Tor hidden services.
                  </p>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <label style={{ fontSize: "0.8125rem", color: "var(--text-secondary)" }}>Target:</label>
                  <select
                    value={graphTarget}
                    onChange={(e) => {
                      setGraphTarget(e.target.value);
                      loadGraph(e.target.value);
                    }}
                    className="input mono"
                    style={{ minWidth: "260px" }}
                  >
                    <option value="">-- Select Target --</option>
                    {targets.map((t) => (
                      <option key={t.target} value={t.target}>
                        {t.target}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => loadGraph(graphTarget)}
                    disabled={!graphTarget || graphLoading}
                    className="btn btn-secondary"
                    style={{ padding: "6px 12px", fontSize: "0.75rem" }}
                  >
                    <RefreshCw size={14} /> Refresh
                  </button>
                </div>
              </div>
            </div>

            <EvidenceGraph data={graphData} target={graphTarget} loading={graphLoading} />
          </div>
        )}

        {/* TAB 5: API SETTINGS */}
        {activeTab === "settings" && (
          <div style={{ maxWidth: "600px", margin: "0 auto" }}>
            <div className="card">
              <h3 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "8px" }}>
                OnionSec Daemon API Configuration
              </h3>
              <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginBottom: "20px" }}>
                Connect this dashboard to your local or remote <code>cmd/onionsecd/</code> instance.
              </p>

              <form onSubmit={handleSaveSettings} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.875rem", fontWeight: 500, marginBottom: "6px" }}>
                    API Server Base URL
                  </label>
                  <input
                    type="text"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder="http://127.0.0.1:8080"
                    className="input"
                    style={{ width: "100%" }}
                  />
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    Base URL of the running onionsecd daemon.
                  </span>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.875rem", fontWeight: 500, marginBottom: "6px" }}>
                    API Bearer Token / Secret Key (Optional)
                  </label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="ONIONSEC_API_KEY"
                    className="input"
                    style={{ width: "100%" }}
                  />
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    Required if the daemon was started with <code>-key</code>.
                  </span>
                </div>

                {settingsMessage && (
                  <div
                    style={{
                      padding: "10px 14px",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                      backgroundColor: daemonHealthy ? "rgba(16, 185, 129, 0.1)" : "rgba(244, 63, 94, 0.1)",
                      color: daemonHealthy ? "#34d399" : "#fb7185",
                    }}
                  >
                    {settingsMessage}
                  </div>
                )}

                <div style={{ display: "flex", gap: "12px", marginTop: "12px" }}>
                  <button type="submit" className="btn btn-primary">
                    Save & Test Connection
                  </button>
                  <button
                    type="button"
                    onClick={checkHealthAndLoadData}
                    className="btn btn-secondary"
                  >
                    Reload Data
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </main>

      {/* NEW SCAN MODAL */}
      {showScanModal && (
        <div className="modal-backdrop" onClick={() => setShowScanModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: "20px", borderBottom: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Shield style={{ color: "var(--accent-cyan)" }} size={20} />
                <h3 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Launch OnionSec Scan</h3>
              </div>
              <button
                onClick={() => setShowScanModal(false)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "1.25rem" }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleStartScan} style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "16px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.875rem", fontWeight: 500, marginBottom: "6px" }}>
                  Target Onion Address <span style={{ color: "#fb7185" }}>*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. expyuzz5wqqfdgah56...onion"
                  value={newScanTarget}
                  onChange={(e) => setNewScanTarget(e.target.value)}
                  className="input mono"
                  style={{ width: "100%" }}
                />
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  Must be an authorized Tor v3 hidden service.
                </span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.875rem", fontWeight: 500, marginBottom: "6px" }}>
                    Max Pages Limit
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={newScanMaxPages}
                    onChange={(e) => setNewScanMaxPages(Number(e.target.value))}
                    className="input"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.875rem", fontWeight: 500, marginBottom: "6px" }}>
                    Per-Page Timeout
                  </label>
                  <input
                    type="text"
                    value={newScanTimeout}
                    onChange={(e) => setNewScanTimeout(e.target.value)}
                    placeholder="10s"
                    className="input"
                    style={{ width: "100%" }}
                  />
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input
                  type="checkbox"
                  id="asyncScan"
                  checked={newScanAsync}
                  onChange={(e) => setNewScanAsync(e.target.checked)}
                />
                <label htmlFor="asyncScan" style={{ fontSize: "0.875rem", cursor: "pointer" }}>
                  Run in background (Async mode)
                </label>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", marginTop: "12px" }}>
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  className="btn btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={scanSubmitting}
                  className="btn btn-primary"
                >
                  {scanSubmitting ? "Scanning..." : "Start Security Scan"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* INSPECT SCAN DETAIL MODAL */}
      {selectedScan && (
        <div className="modal-backdrop" onClick={() => setSelectedScan(null)}>
          <div className="modal-content" style={{ maxWidth: "800px" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ padding: "20px", borderBottom: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <h3 style={{ fontSize: "1.125rem", fontWeight: 600 }}>Scan Report</h3>
                  {getRiskScoreBadge(selectedScan.risk_score)}
                </div>
                <div className="mono" style={{ fontSize: "0.8125rem", color: "var(--accent-cyan)", marginTop: "4px" }}>
                  {selectedScan.target}
                </div>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "1.25rem" }}
              >
                ✕
              </button>
            </div>

            <div style={{ padding: "20px" }}>
              {/* Scan summary metrics */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginBottom: "20px", backgroundColor: "var(--bg-card)", padding: "12px", borderRadius: "6px" }}>
                <div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Scan ID</div>
                  <div className="mono" style={{ fontSize: "0.8125rem" }}>{selectedScan.id}</div>
                </div>
                <div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Pages Crawled</div>
                  <div style={{ fontSize: "0.875rem", fontWeight: 600 }}>{selectedScan.pages_seen || 1}</div>
                </div>
                <div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Completed At</div>
                  <div style={{ fontSize: "0.75rem" }}>
                    {selectedScan.ended_at ? new Date(selectedScan.ended_at).toLocaleString() : "N/A"}
                  </div>
                </div>
              </div>

              {/* Findings list */}
              <h4 style={{ fontSize: "0.95rem", fontWeight: 600, marginBottom: "12px" }}>
                Findings ({selectedScan.findings?.length || 0})
              </h4>

              {selectedScan.findings && selectedScan.findings.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "400px", overflowY: "auto" }}>
                  {selectedScan.findings.map((f, i) => (
                    <div
                      key={i}
                      style={{
                        padding: "12px",
                        backgroundColor: "var(--bg-card)",
                        border: "1px solid var(--border-color)",
                        borderRadius: "6px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          {getSeverityBadge(f.severity)}
                          <span className="mono" style={{ fontWeight: 600, fontSize: "0.875rem" }}>{f.id}</span>
                          <span className="badge badge-neutral">{f.analyzer}</span>
                        </div>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                          Confidence: {Math.round(f.confidence * 100)}%
                        </span>
                      </div>
                      <div style={{ fontWeight: 500, fontSize: "0.875rem", marginBottom: "4px" }}>{f.title}</div>
                      {f.evidence && f.evidence.length > 0 && (
                        <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "6px" }}>
                          <strong>Evidence: </strong>
                          <span className="mono">{f.evidence.map((e) => e.description).join(", ")}</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ textAlign: "center", padding: "20px 0", color: "var(--text-muted)" }}>
                  No security issues found on this scan.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer
        style={{
          borderTop: "1px solid var(--border-color)",
          backgroundColor: "var(--bg-secondary)",
          padding: "12px 24px",
          textAlign: "center",
          fontSize: "0.75rem",
          color: "var(--text-muted)",
        }}
      >
        OnionSec Dashboard · Consuming OnionSec HTTP API · Safe, Authorized Tor Hidden Service Auditing
      </footer>
    </div>
  );
}

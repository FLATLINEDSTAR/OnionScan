"use client";

import React, { useEffect, useRef, useState } from "react";
import cytoscape, { Core, EventObject } from "cytoscape";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Download,
  Info,
  Layers,
  Network
} from "lucide-react";
import { GraphResponse } from "../../lib/api";

interface EvidenceGraphProps {
  data: GraphResponse | null;
  target: string;
  loading: boolean;
}

export default function EvidenceGraph({ data, target, loading }: EvidenceGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [selectedElement, setSelectedElement] = useState<any | null>(null);
  const [layoutName, setLayoutName] = useState<string>("cose");

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    if (!data || !data.elements || data.elements.nodes.length === 0) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      setSelectedElement(null);
      return;
    }

    // Destroy existing instance before recreation
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const elements = [
      ...data.elements.nodes.map((n) => ({
        group: "nodes" as const,
        data: n.data,
      })),
      ...data.elements.edges.map((e) => ({
        group: "edges" as const,
        data: e.data,
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "label": "data(label)",
            "color": "#f8fafc",
            "font-size": "11px",
            "font-family": "ui-monospace, monospace",
            "text-valign": "bottom",
            "text-margin-y": 6,
            "text-background-opacity": 0.7,
            "text-background-color": "#090d16",
            "text-background-padding": "2px",
            "text-background-shape": "roundrectangle",
            "background-color": "#38bdf8",
            "border-width": 2,
            "border-color": "#0284c7",
            "width": 36,
            "height": 36,
          },
        },
        {
          selector: "node[type = 'target']",
          style: {
            "background-color": "#06b6d4",
            "border-width": 4,
            "border-color": "#22d3ee",
            "width": 52,
            "height": 52,
            "shape": "ellipse",
            "font-weight": "bold",
            "font-size": "13px",
          },
        },
        {
          selector: "node[type = 'peer']",
          style: {
            "background-color": "#f43f5e",
            "border-width": 3,
            "border-color": "#fb7185",
            "width": 44,
            "height": 44,
            "shape": "ellipse",
            "font-size": "12px",
          },
        },
        {
          selector: "node[type = 'ip']",
          style: {
            "background-color": "#10b981",
            "border-color": "#34d399",
            "shape": "diamond",
            "width": 38,
            "height": 38,
          },
        },
        {
          selector: "node[type = 'tls']",
          style: {
            "background-color": "#8b5cf6",
            "border-color": "#a78bfa",
            "shape": "hexagon",
            "width": 38,
            "height": 38,
          },
        },
        {
          selector: "node[type = 'fingerprint']",
          style: {
            "background-color": "#f59e0b",
            "border-color": "#fbbf24",
            "shape": "roundrectangle",
            "width": 36,
            "height": 36,
          },
        },
        {
          selector: "node[type = 'email']",
          style: {
            "background-color": "#ec4899",
            "border-color": "#f472b6",
            "shape": "tag",
            "width": 36,
            "height": 36,
          },
        },
        {
          selector: "edge",
          style: {
            "width": 2,
            "line-color": "#334155",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(label)",
            "font-size": "9px",
            "color": "#64748b",
            "text-background-opacity": 0.8,
            "text-background-color": "#0f172a",
            "text-background-padding": "2px",
          },
        },
        {
          selector: "edge[label = 'exhibits']",
          style: {
            "line-color": "#0ea5e9",
            "target-arrow-color": "#0ea5e9",
          },
        },
        {
          selector: "edge[label = 'co-occurs']",
          style: {
            "line-color": "#f43f5e",
            "target-arrow-color": "#f43f5e",
            "line-style": "dashed",
            "width": 2.5,
          },
        },
        {
          selector: ":selected",
          style: {
            "border-color": "#ffffff",
            "border-width": 4,
            "line-color": "#38bdf8",
            "target-arrow-color": "#38bdf8",
          },
        },
      ],
      layout: {
        name: layoutName,
        animate: true,
        animationDuration: 500,
        padding: 50,
      } as any,
    });

    // Tap events
    cy.on("tap", "node", (evt: EventObject) => {
      const node = evt.target;
      setSelectedElement({
        type: "node",
        id: node.id(),
        label: node.data("label"),
        category: node.data("type"),
        degree: node.degree(),
      });
    });

    cy.on("tap", "edge", (evt: EventObject) => {
      const edge = evt.target;
      setSelectedElement({
        type: "edge",
        id: edge.id(),
        label: edge.data("label"),
        source: edge.data("source"),
        target: edge.data("target"),
      });
    });

    cy.on("tap", (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedElement(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data, layoutName]);

  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 1.25);
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 0.8);
    }
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 40);
    }
  };

  const handleResetLayout = () => {
    if (cyRef.current) {
      cyRef.current.layout({ name: layoutName, animate: true } as any).run();
    }
  };

  const handleExportPNG = () => {
    if (cyRef.current) {
      const png64 = cyRef.current.png({ bg: "#090d16", full: true, scale: 2 });
      const link = document.createElement("a");
      link.href = png64;
      link.download = `onionsec-graph-${target || "target"}.png`;
      link.click();
    }
  };

  const nodeCount = data?.elements?.nodes?.length || 0;
  const edgeCount = data?.elements?.edges?.length || 0;
  const peerCount = data?.elements?.nodes?.filter((n) => n.data.type === "peer").length || 0;

  return (
    <div style={{ position: "relative", width: "100%", height: "650px", backgroundColor: "#060911", borderRadius: "8px", border: "1px solid var(--border-color)", overflow: "hidden" }}>
      {/* Canvas container */}
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {/* Loading overlay */}
      {loading && (
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, backgroundColor: "rgba(9, 13, 22, 0.8)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--accent-cyan)", fontSize: "0.95rem" }}>
            <Network className="animate-spin" size={24} />
            <span>Constructing evidence graph...</span>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && (!data || nodeCount === 0) && (
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", zIndex: 5 }}>
          <Network size={48} style={{ marginBottom: "12px", opacity: 0.4 }} />
          <div style={{ fontSize: "1rem", fontWeight: 500 }}>No Evidence Graph Available</div>
          <div style={{ fontSize: "0.8125rem", marginTop: "4px" }}>
            Select a target with recorded scan evidence to visualize correlation nodes.
          </div>
        </div>
      )}

      {/* Top Floating Control Bar */}
      <div style={{ position: "absolute", top: "16px", left: "16px", display: "flex", gap: "8px", zIndex: 20 }}>
        <button onClick={handleZoomIn} title="Zoom In" className="btn btn-secondary" style={{ padding: "6px 10px" }}>
          <ZoomIn size={16} />
        </button>
        <button onClick={handleZoomOut} title="Zoom Out" className="btn btn-secondary" style={{ padding: "6px 10px" }}>
          <ZoomOut size={16} />
        </button>
        <button onClick={handleFit} title="Fit to Canvas" className="btn btn-secondary" style={{ padding: "6px 10px" }}>
          <Maximize2 size={16} />
        </button>
        <button onClick={handleResetLayout} title="Rearrange Layout" className="btn btn-secondary" style={{ padding: "6px 10px" }}>
          <RotateCcw size={16} />
        </button>
        <button onClick={handleExportPNG} title="Download Graph PNG" className="btn btn-secondary" style={{ padding: "6px 10px" }}>
          <Download size={16} />
        </button>

        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value)}
          className="input"
          style={{ padding: "4px 8px", fontSize: "0.75rem", backgroundColor: "var(--bg-secondary)" }}
        >
          <option value="cose">Force-Directed (Cose)</option>
          <option value="concentric">Concentric Circles</option>
          <option value="circle">Circular Ring</option>
          <option value="breadthfirst">Hierarchical Tree</option>
          <option value="grid">Grid</option>
        </select>
      </div>

      {/* Graph Legend */}
      <div
        style={{
          position: "absolute",
          top: "16px",
          right: "16px",
          backgroundColor: "rgba(15, 23, 42, 0.9)",
          backdropFilter: "blur(4px)",
          border: "1px solid var(--border-color)",
          borderRadius: "6px",
          padding: "10px 14px",
          fontSize: "0.75rem",
          display: "flex",
          flexDirection: "column",
          gap: "6px",
          zIndex: 20,
        }}
      >
        <div style={{ fontWeight: 600, color: "var(--text-secondary)", marginBottom: "2px" }}>Graph Legend</div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", backgroundColor: "#06b6d4" }} />
          <span>Audited Target</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", backgroundColor: "#f43f5e" }} />
          <span>Co-Occurring Peer</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 10, height: 10, transform: "rotate(45deg)", backgroundColor: "#10b981" }} />
          <span>IP Address</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 10, height: 10, backgroundColor: "#8b5cf6" }} />
          <span>TLS Certificate</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 10, height: 10, backgroundColor: "#f59e0b" }} />
          <span>Header / Fingerprint</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ width: 16, height: 2, backgroundColor: "#f43f5e", borderBottom: "1px dashed #f43f5e" }} />
          <span>Co-occurrence Link</span>
        </div>
      </div>

      {/* Graph Stats Bar */}
      <div
        style={{
          position: "absolute",
          bottom: "16px",
          left: "16px",
          backgroundColor: "rgba(15, 23, 42, 0.9)",
          border: "1px solid var(--border-color)",
          borderRadius: "6px",
          padding: "6px 12px",
          fontSize: "0.75rem",
          display: "flex",
          gap: "16px",
          color: "var(--text-secondary)",
          zIndex: 20,
        }}
      >
        <span>Nodes: <strong style={{ color: "var(--text-primary)" }}>{nodeCount}</strong></span>
        <span>Edges: <strong style={{ color: "var(--text-primary)" }}>{edgeCount}</strong></span>
        <span>Connected Peers: <strong style={{ color: peerCount > 0 ? "#fb7185" : "var(--text-primary)" }}>{peerCount}</strong></span>
      </div>

      {/* Selected Element Detail Inspector */}
      {selectedElement && (
        <div
          style={{
            position: "absolute",
            bottom: "16px",
            right: "16px",
            backgroundColor: "var(--bg-secondary)",
            border: "1px solid var(--accent-cyan)",
            borderRadius: "8px",
            padding: "14px",
            maxWidth: "320px",
            width: "100%",
            zIndex: 25,
            boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <Info size={14} style={{ color: "var(--accent-cyan)" }} />
              <span style={{ fontWeight: 600, fontSize: "0.8125rem", textTransform: "uppercase" }}>
                {selectedElement.type === "node" ? `Node: ${selectedElement.category}` : "Edge Connection"}
              </span>
            </div>
            <button
              onClick={() => setSelectedElement(null)}
              style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
            >
              ✕
            </button>
          </div>

          <div className="mono" style={{ fontSize: "0.8125rem", color: "var(--text-primary)", wordBreak: "break-all", marginBottom: "6px" }}>
            {selectedElement.label || selectedElement.id}
          </div>

          {selectedElement.type === "node" && (
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Connections: {selectedElement.degree} link(s)
            </div>
          )}

          {selectedElement.type === "edge" && (
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              <div>From: <span className="mono">{selectedElement.source}</span></div>
              <div>To: <span className="mono">{selectedElement.target}</span></div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

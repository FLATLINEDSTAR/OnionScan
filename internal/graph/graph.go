// Package graph constructs and renders evidence graphs linking onion services
// to observed infrastructure, certificates, fingerprints, and identifiers.
package graph

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/AryanXCode646/OnionScan/internal/model"
	"github.com/AryanXCode646/OnionScan/internal/storage"
)

// EvidenceNode represents a distinct evidence item and any peer targets sharing it.
type EvidenceNode struct {
	Type  model.EvidenceType `json:"type"`
	Value string             `json:"value"`
	Peers []string           `json:"peers"`
}

// Graph contains the graph data for a target service.
type Graph struct {
	Target string         `json:"target"`
	Nodes  []EvidenceNode `json:"nodes"`
	Peers  []string       `json:"peers"`
}

// BuildGraph constructs an evidence graph for target using the scan history and evidence index in store.
func BuildGraph(targetOnion string, store *storage.Store) (*Graph, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required to build evidence graph")
	}

	latest, ok, err := store.Latest(targetOnion)
	if err != nil {
		return nil, fmt.Errorf("retrieve latest scan for %s: %w", targetOnion, err)
	}
	if !ok {
		return nil, fmt.Errorf("no scan history found for target %q (run `onionsec scan %s` first)", targetOnion, targetOnion)
	}

	type evKey struct {
		evType model.EvidenceType
		val    string
	}

	seenKeys := make(map[evKey]bool)
	var nodes []EvidenceNode
	allPeers := make(map[string]bool)

	for _, f := range latest.Findings {
		for _, ev := range f.Evidence {
			// Redact/exclude credentials and meta-evidence from graph
			if ev.Type == model.EvidenceCredential || ev.Source == "cross-target correlation" {
				continue
			}

			val := strings.TrimSpace(ev.Description)
			if val == "" {
				continue
			}

			k := evKey{evType: ev.Type, val: val}
			if seenKeys[k] {
				continue
			}
			seenKeys[k] = true

			links, err := store.FindCoOccurringTargets(ev.Type, val)
			if err != nil {
				continue
			}

			var peers []string
			for _, l := range links {
				if l.Onion != "" && !strings.EqualFold(l.Onion, targetOnion) {
					peers = append(peers, l.Onion)
					allPeers[l.Onion] = true
				}
			}
			sort.Strings(peers)

			nodes = append(nodes, EvidenceNode{
				Type:  ev.Type,
				Value: val,
				Peers: peers,
			})
		}
	}

	var peerList []string
	for p := range allPeers {
		peerList = append(peerList, p)
	}
	sort.Strings(peerList)

	// Sort nodes by type and then value for deterministic rendering
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Type != nodes[j].Type {
			return nodes[i].Type < nodes[j].Type
		}
		return nodes[i].Value < nodes[j].Value
	})

	return &Graph{
		Target: targetOnion,
		Nodes:  nodes,
		Peers:  peerList,
	}, nil
}

// RenderText formats the evidence graph as an indented ASCII tree.
func RenderText(w io.Writer, g *Graph) error {
	if _, err := fmt.Fprintf(w, "target: %s\n", g.Target); err != nil {
		return err
	}

	if len(g.Nodes) == 0 {
		_, err := fmt.Fprintln(w, "└── (no evidence recorded)")
		return err
	}

	for i, node := range g.Nodes {
		branch := "├── "
		if i == len(g.Nodes)-1 {
			branch = "└── "
		}

		peerInfo := "unique to target"
		if len(node.Peers) > 0 {
			peerInfo = fmt.Sprintf("also seen on %s", strings.Join(node.Peers, ", "))
		}

		if _, err := fmt.Fprintf(w, "%s%s: %s (%s)\n", branch, node.Type, node.Value, peerInfo); err != nil {
			return err
		}
	}
	return nil
}

// RenderDOT formats the evidence graph as a Graphviz DOT diagram.
func RenderDOT(w io.Writer, g *Graph) error {
	var sb strings.Builder
	sb.WriteString("graph G {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [fontname=\"Helvetica,Arial,sans-serif\", fontsize=10];\n")
	sb.WriteString("  edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=9];\n\n")

	// Target node (primary)
	targetID := quoteDOT(g.Target)
	sb.WriteString(fmt.Sprintf("  %s [shape=box, style=filled, fillcolor=\"#d1e7dd\", label=\"%s\\n(target)\"];\n", targetID, escapeQuotes(g.Target)))

	// Peer target nodes
	for _, p := range g.Peers {
		peerID := quoteDOT(p)
		sb.WriteString(fmt.Sprintf("  %s [shape=box, style=filled, fillcolor=\"#f8d7da\", label=\"%s\\n(peer)\"];\n", peerID, escapeQuotes(p)))
	}

	if len(g.Nodes) > 0 {
		sb.WriteString("\n  // Evidence nodes and relationships\n")
	}

	for i, node := range g.Nodes {
		nodeID := quoteDOT(fmt.Sprintf("ev_%d", i))
		label := escapeQuotes(fmt.Sprintf("%s\\n%s", node.Type, node.Value))
		fillColor := "#fff3cd" // default light yellow
		if len(node.Peers) > 0 {
			fillColor = "#ffeaa7" // shared evidence
		}

		sb.WriteString(fmt.Sprintf("  %s [shape=ellipse, style=filled, fillcolor=\"%s\", label=\"%s\"];\n", nodeID, fillColor, label))
		sb.WriteString(fmt.Sprintf("  %s -- %s;\n", targetID, nodeID))

		for _, p := range node.Peers {
			sb.WriteString(fmt.Sprintf("  %s -- %s [style=dashed, color=\"#e74c3c\"];\n", quoteDOT(p), nodeID))
		}
	}

	sb.WriteString("}\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

func quoteDOT(s string) string {
	return `"` + escapeQuotes(s) + `"`
}

func escapeQuotes(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

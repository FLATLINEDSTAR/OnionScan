// Package diff provides comparison and diffing capabilities between two scan runs
// of an onion target, identifying new, removed, and changed security findings.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// ChangedFinding describes modifications to an existing finding between two scans.
type ChangedFinding struct {
	ID         string        `json:"id"`
	Title      string        `json:"title"`
	OldFinding model.Finding `json:"old_finding"`
	NewFinding model.Finding `json:"new_finding"`
	Changes    []string      `json:"changes"`
}

// DiffResult holds the comprehensive comparison between two scans.
type DiffResult struct {
	Target          string           `json:"target"`
	IsInitialScan   bool             `json:"is_initial_scan"`
	OldScanID       string           `json:"old_scan_id,omitempty"`
	NewScanID       string           `json:"new_scan_id"`
	OldScanTime     time.Time        `json:"old_scan_time,omitempty"`
	NewScanTime     time.Time        `json:"new_scan_time"`
	OldRiskScore    int              `json:"old_risk_score"`
	NewRiskScore    int              `json:"new_risk_score"`
	ScoreDelta      int              `json:"score_delta"`
	NewFindings     []model.Finding  `json:"new_findings"`
	RemovedFindings []model.Finding  `json:"removed_findings"`
	ChangedFindings []ChangedFinding `json:"changed_findings"`
	UnchangedCount  int              `json:"unchanged_count"`
}

// HasChanges returns true if there are any new, removed, or changed findings or a score change.
func (d DiffResult) HasChanges() bool {
	return len(d.NewFindings) > 0 || len(d.RemovedFindings) > 0 || len(d.ChangedFindings) > 0 || d.ScoreDelta != 0
}

// Diff compares a prior scan (if available) with a newly executed scan.
func Diff(oldScan model.ScanResult, hasOld bool, newScan model.ScanResult) DiffResult {
	newScanID := newScan.EndedAt.UTC().Format("20060102T150405Z")

	if !hasOld {
		return DiffResult{
			Target:         newScan.Target.Onion,
			IsInitialScan:  true,
			NewScanID:      newScanID,
			NewScanTime:    newScan.EndedAt,
			NewRiskScore:   newScan.RiskScore,
			ScoreDelta:     newScan.RiskScore,
			NewFindings:    newScan.Findings,
			UnchangedCount: 0,
		}
	}

	oldScanID := oldScan.EndedAt.UTC().Format("20060102T150405Z")

	oldMap := make(map[string]model.Finding)
	for _, f := range oldScan.Findings {
		oldMap[f.ID] = f
	}

	newMap := make(map[string]model.Finding)
	for _, f := range newScan.Findings {
		newMap[f.ID] = f
	}

	var newFindings []model.Finding
	var changedFindings []ChangedFinding
	unchangedCount := 0

	// Check each finding in new scan against old scan
	for _, nf := range newScan.Findings {
		of, exists := oldMap[nf.ID]
		if !exists {
			newFindings = append(newFindings, nf)
			continue
		}

		changes := inspectChanges(of, nf)
		if len(changes) > 0 {
			changedFindings = append(changedFindings, ChangedFinding{
				ID:         nf.ID,
				Title:      nf.Title,
				OldFinding: of,
				NewFinding: nf,
				Changes:    changes,
			})
		} else {
			unchangedCount++
		}
	}

	// Check for removed findings
	var removedFindings []model.Finding
	for _, of := range oldScan.Findings {
		if _, exists := newMap[of.ID]; !exists {
			removedFindings = append(removedFindings, of)
		}
	}

	return DiffResult{
		Target:          newScan.Target.Onion,
		IsInitialScan:   false,
		OldScanID:       oldScanID,
		NewScanID:       newScanID,
		OldScanTime:     oldScan.EndedAt,
		NewScanTime:     newScan.EndedAt,
		OldRiskScore:    oldScan.RiskScore,
		NewRiskScore:    newScan.RiskScore,
		ScoreDelta:      newScan.RiskScore - oldScan.RiskScore,
		NewFindings:     newFindings,
		RemovedFindings: removedFindings,
		ChangedFindings: changedFindings,
		UnchangedCount:  unchangedCount,
	}
}

func inspectChanges(oldF, newF model.Finding) []string {
	var changes []string

	if oldF.Severity != newF.Severity {
		changes = append(changes, fmt.Sprintf("Severity changed from %s to %s", oldF.Severity, newF.Severity))
	}

	if math.Abs(oldF.Confidence-newF.Confidence) >= 0.05 {
		changes = append(changes, fmt.Sprintf("Confidence shifted from %.2f to %.2f", oldF.Confidence, newF.Confidence))
	}

	oldEvMap := make(map[string]bool)
	for _, e := range oldF.Evidence {
		oldEvMap[string(e.Type)+":"+e.Description] = true
	}

	newEvCount := 0
	for _, e := range newF.Evidence {
		key := string(e.Type) + ":" + e.Description
		if !oldEvMap[key] {
			newEvCount++
		}
	}

	newEvMap := make(map[string]bool)
	for _, e := range newF.Evidence {
		newEvMap[string(e.Type)+":"+e.Description] = true
	}

	removedEvCount := 0
	for _, e := range oldF.Evidence {
		key := string(e.Type) + ":" + e.Description
		if !newEvMap[key] {
			removedEvCount++
		}
	}

	if newEvCount > 0 {
		changes = append(changes, fmt.Sprintf("%d new evidence items observed", newEvCount))
	}
	if removedEvCount > 0 {
		changes = append(changes, fmt.Sprintf("%d prior evidence items resolved", removedEvCount))
	}

	return changes
}

// RenderText outputs a human-readable diff report with NEW/REMOVED/CHANGED sections.
func RenderText(w io.Writer, d DiffResult) error {
	sep := strings.Repeat("=", 78)
	fmt.Fprintf(w, "%s\n", sep)
	fmt.Fprintf(w, "SCAN DIFF REPORT: %s\n", d.Target)

	if d.IsInitialScan {
		fmt.Fprintf(w, "Scan ID:     %s (%s)\n", d.NewScanID, d.NewScanTime.UTC().Format(time.RFC3339))
		fmt.Fprintf(w, "Risk Score:  %d / 100\n", d.NewRiskScore)
		fmt.Fprintf(w, "Status:      Initial scan recorded (baseline established)\n")
		fmt.Fprintf(w, "%s\n\n", sep)

		if len(d.NewFindings) == 0 {
			fmt.Fprintln(w, "No security findings recorded in initial scan.")
			return nil
		}

		fmt.Fprintf(w, "[+] INITIAL FINDINGS (%d):\n", len(d.NewFindings))
		for _, f := range d.NewFindings {
			printFindingText(w, f)
		}
		return nil
	}

	deltaStr := fmt.Sprintf("%+d", d.ScoreDelta)
	if d.ScoreDelta == 0 {
		deltaStr = "unchanged"
	}
	fmt.Fprintf(w, "Baseline:    %s (%s) [Score: %d]\n", d.OldScanID, d.OldScanTime.UTC().Format(time.RFC3339), d.OldRiskScore)
	fmt.Fprintf(w, "Current:     %s (%s) [Score: %d, Delta: %s]\n", d.NewScanID, d.NewScanTime.UTC().Format(time.RFC3339), d.NewRiskScore, deltaStr)
	fmt.Fprintf(w, "%s\n\n", sep)

	if !d.HasChanges() {
		fmt.Fprintln(w, "No security or infrastructure changes detected since baseline scan.")
		return nil
	}

	if len(d.NewFindings) > 0 {
		fmt.Fprintf(w, "[+] NEW FINDINGS (%d):\n", len(d.NewFindings))
		for _, f := range d.NewFindings {
			printFindingText(w, f)
		}
		fmt.Fprintln(w)
	}

	if len(d.RemovedFindings) > 0 {
		fmt.Fprintf(w, "[-] REMOVED / RESOLVED FINDINGS (%d):\n", len(d.RemovedFindings))
		for _, f := range d.RemovedFindings {
			printFindingText(w, f)
		}
		fmt.Fprintln(w)
	}

	if len(d.ChangedFindings) > 0 {
		fmt.Fprintf(w, "[~] CHANGED FINDINGS (%d):\n", len(d.ChangedFindings))
		for _, cf := range d.ChangedFindings {
			fmt.Fprintf(w, "  • [%s] %s: %s\n", cf.NewFinding.Severity, cf.ID, cf.Title)
			for _, ch := range cf.Changes {
				fmt.Fprintf(w, "    - %s\n", ch)
			}
			fmt.Fprintln(w)
		}
	}

	if d.UnchangedCount > 0 {
		fmt.Fprintf(w, "Unchanged findings: %d\n", d.UnchangedCount)
	}

	return nil
}

func printFindingText(w io.Writer, f model.Finding) {
	fmt.Fprintf(w, "  • [%s] %s: %s\n", f.Severity, f.ID, f.Title)
	fmt.Fprintf(w, "    Confidence: %.2f | Analyzer: %s\n", f.Confidence, f.Analyzer)
	if len(f.Evidence) > 0 {
		maxEv := 3
		if len(f.Evidence) < maxEv {
			maxEv = len(f.Evidence)
		}
		for i := 0; i < maxEv; i++ {
			fmt.Fprintf(w, "    Evidence: %s\n", f.Evidence[i].Description)
		}
		if len(f.Evidence) > maxEv {
			fmt.Fprintf(w, "    ... and %d more evidence items\n", len(f.Evidence)-maxEv)
		}
	}
	fmt.Fprintln(w)
}

// RenderJSON writes the diff result as indented JSON.
func RenderJSON(w io.Writer, d DiffResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// RenderMarkdown outputs a formatted markdown diff report.
func RenderMarkdown(w io.Writer, d DiffResult) error {
	fmt.Fprintf(w, "# Scan Diff Report: `%s`\n\n", d.Target)

	if d.IsInitialScan {
		fmt.Fprintf(w, "- **Scan ID:** `%s` (%s)\n", d.NewScanID, d.NewScanTime.UTC().Format(time.RFC3339))
		fmt.Fprintf(w, "- **Risk Score:** %d / 100\n", d.NewRiskScore)
		fmt.Fprintf(w, "- **Status:** Initial scan recorded (baseline established)\n\n")

		if len(d.NewFindings) == 0 {
			fmt.Fprintln(w, "No findings recorded in initial scan.")
			return nil
		}
		fmt.Fprintln(w, "## Baseline Findings")
		renderFindingTable(w, d.NewFindings)
		return nil
	}

	deltaStr := fmt.Sprintf("%+d", d.ScoreDelta)
	if d.ScoreDelta == 0 {
		deltaStr = "unchanged"
	}

	fmt.Fprintf(w, "- **Baseline Scan:** `%s` (%s) — Score: %d\n", d.OldScanID, d.OldScanTime.UTC().Format(time.RFC3339), d.OldRiskScore)
	fmt.Fprintf(w, "- **Current Scan:** `%s` (%s) — Score: %d (%s)\n\n", d.NewScanID, d.NewScanTime.UTC().Format(time.RFC3339), d.NewRiskScore, deltaStr)

	if !d.HasChanges() {
		fmt.Fprintln(w, "No security or infrastructure changes detected between scans.")
		return nil
	}

	if len(d.NewFindings) > 0 {
		fmt.Fprintf(w, "## 🟢 New Findings (%d)\n\n", len(d.NewFindings))
		renderFindingTable(w, d.NewFindings)
	}

	if len(d.RemovedFindings) > 0 {
		fmt.Fprintf(w, "## 🔴 Resolved / Removed Findings (%d)\n\n", len(d.RemovedFindings))
		renderFindingTable(w, d.RemovedFindings)
	}

	if len(d.ChangedFindings) > 0 {
		fmt.Fprintf(w, "## 🟡 Changed Findings (%d)\n\n", len(d.ChangedFindings))
		for _, cf := range d.ChangedFindings {
			fmt.Fprintf(w, "### `%s` %s\n", cf.ID, cf.Title)
			for _, ch := range cf.Changes {
				fmt.Fprintf(w, "- %s\n", ch)
			}
			fmt.Fprintln(w)
		}
	}

	return nil
}

func renderFindingTable(w io.Writer, findings []model.Finding) {
	fmt.Fprintln(w, "| ID | Title | Severity | Confidence | Analyzer |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, f := range findings {
		fmt.Fprintf(w, "| `%s` | %s | %s | %.2f | %s |\n", f.ID, f.Title, f.Severity, f.Confidence, f.Analyzer)
	}
	fmt.Fprintln(w)
}

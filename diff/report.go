package diff

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Mask is the placeholder rendered for sensitive values when masking is on
// (the default). It deliberately carries no information about length or type.
const Mask = "***MASKED***"

// ReportOptions controls human-readable rendering of a Result.
type ReportOptions struct {
	// ShowSensitive renders real values for sensitive keys. When false (the
	// safe default) sensitive values are replaced with Mask.
	ShowSensitive bool
	// ShowEqual includes equal leaves in the report. By default only
	// differences are printed.
	ShowEqual bool
}

// RenderReport writes a grouped, human-readable diff report to w.
//
// Entries are grouped into three sections in this order: values that differ,
// leaves present on only one side, and equal leaves (only when
// ReportOptions.ShowEqual is set). Sensitive values are masked unless
// ShowSensitive is explicitly enabled.
func RenderReport(w io.Writer, result Result, opts ReportOptions) error {
	groups := result.ByChange()

	sections := []struct {
		title   string
		change  ChangeType
		entries []Entry
	}{
		{"Changed values", ValueChanged, groups[ValueChanged]},
		{"Only in A (left file)", OnlyInA, groups[OnlyInA]},
		{"Only in B (right file)", OnlyInB, groups[OnlyInB]},
	}
	if opts.ShowEqual {
		sections = append(sections, struct {
			title   string
			change  ChangeType
			entries []Entry
		}{"Equal values", Equal, groups[Equal]})
	}

	for _, section := range sections {
		entries := section.entries
		sortEntries(entries)
		if len(entries) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s (%d):\n", section.title, len(entries)); err != nil {
			return err
		}
		for _, e := range entries {
			if err := renderEntry(w, e, opts); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	summary := buildSummary(result)
	_, err := fmt.Fprintln(w, summary)
	return err
}

func renderEntry(w io.Writer, e Entry, opts ReportOptions) error {
	masked := e.Sensitive && !opts.ShowSensitive
	switch e.Change {
	case ValueChanged:
		va := displayValue(e.ValueA, masked)
		vb := displayValue(e.ValueB, masked)
		_, err := fmt.Fprintf(w, "  %s\n    - %s\n    + %s\n", e.PathString(), va, vb)
		return err
	case OnlyInA:
		_, err := fmt.Fprintf(w, "  - %s = %s\n", e.PathString(), displayValue(e.ValueA, masked))
		return err
	case OnlyInB:
		_, err := fmt.Fprintf(w, "  + %s = %s\n", e.PathString(), displayValue(e.ValueB, masked))
		return err
	case Equal:
		_, err := fmt.Fprintf(w, "  = %s = %s\n", e.PathString(), displayValue(e.ValueA, masked))
		return err
	default:
		_, err := fmt.Fprintf(w, "  ? %s\n", e.PathString())
		return err
	}
}

// displayValue renders a leaf value for output, applying the mask.
func displayValue(v interface{}, masked bool) string {
	if masked {
		return Mask
	}
	if v == nil {
		return "null"
	}
	if s, ok := v.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%v", v)
}

func buildSummary(result Result) string {
	groups := result.ByChange()
	parts := []string{
		fmt.Sprintf("changed=%d", len(groups[ValueChanged])),
		fmt.Sprintf("only_in_a=%d", len(groups[OnlyInA])),
		fmt.Sprintf("only_in_b=%d", len(groups[OnlyInB])),
		fmt.Sprintf("equal=%d", len(groups[Equal])),
	}
	return "Summary: " + strings.Join(parts, " ")
}

// sortEntries orders entries by rendered path so output is deterministic
// regardless of map iteration order during the walk.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].PathString() < entries[j].PathString()
	})
}

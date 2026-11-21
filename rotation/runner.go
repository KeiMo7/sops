package rotation

// WorkItem is one path the run may touch. A nil Process means the item is
// recorded as skipped without being processed (used for unsupported formats
// found during a recursive walk).
type WorkItem struct {
	// Path is the path handed to Process (absolute or relative; the runner
	// does not care).
	Path string
	// Record, when non-nil, is written as-is instead of calling Process.
	Skip *Record
}

// FileOutcome is what Process reports for one file.
type FileOutcome struct {
	// Record is the file record. Kind/File/Status are filled in by the
	// runner if the processor left them empty.
	Record Record
	// Err is the rotation error for this file, if any. It is returned from
	// Run so the command layer can aggregate exit codes.
	Err error
	// Abort stops the run after this record is written. No records are
	// produced for the remaining files, which is what keeps an interrupted
	// run from leaving traces of files it never touched.
	Abort bool
}

// RunResult reports what Run did.
type RunResult struct {
	Totals  Totals
	Errors  []error
	Aborted bool
	// Interrupted is set when stop was closed before the run finished. The
	// records for finished files are kept; no summary is written because
	// the run's totals are incomplete.
	Interrupted bool
	// LogErrors holds errors from appending records. They never affect the
	// rotation outcome; the command layer warns about them.
	LogErrors []error
}

// Run processes items in order and appends one record per finished item to
// writer, then a summary record.
//
// The invariant that matters operationally is: a record is appended only after
// its file has been fully processed (including writing the rotated bytes), so
// a crash or abort leaves records for exactly the files that were handled and
// nothing for the rest.
//
// writer may be nil, in which case Run does no recording at all and is just a
// straightforward sequential loop.
func Run(items []WorkItem, rotationID string, writer *RunWriter, process func(WorkItem) FileOutcome, stop <-chan struct{}) RunResult {
	var result RunResult
	for _, item := range items {
		if stop != nil {
			select {
			case <-stop:
				result.Interrupted = true
			default:
			}
			if result.Interrupted {
				break
			}
		}
		var outcome FileOutcome
		if item.Skip != nil {
			outcome.Record = *item.Skip
		} else {
			outcome = process(item)
		}
		record := outcome.Record
		record.normalize()
		record.RotationID = rotationID
		if record.Kind == "" {
			record.Kind = KindFile
		}
		if record.Kind == KindFile && record.File == "" {
			record.File = RelativePath("", item.Path)
		}

		switch record.Status {
		case StatusSuccess:
			result.Totals.Succeeded++
		case StatusSkipped:
			result.Totals.Skipped++
		case StatusFailed:
			result.Totals.Failed++
		}
		result.Totals.Total++
		if outcome.Err != nil {
			result.Errors = append(result.Errors, outcome.Err)
		}

		if writer != nil {
			if err := writer.Write(record); err != nil {
				result.LogErrors = append(result.LogErrors, err)
			}
		}
		if outcome.Abort {
			result.Aborted = true
			break
		}
	}

	if writer != nil && !result.Interrupted && !result.Aborted {
		summary := Record{
			Kind:       KindSummary,
			RotationID: rotationID,
			Totals:     &result.Totals,
		}
		summary.normalize()
		if err := writer.Write(summary); err != nil {
			result.LogErrors = append(result.LogErrors, err)
		}
	}
	return result
}

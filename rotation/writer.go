package rotation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Writer appends records to a rotation trail.
//
// Failures are reported to the caller but never abort the rotation itself:
// the command layer logs a warning, keeps the record pending, and retries or
// spools it for a later replay.
type Writer struct {
	dir string
	mu  sync.Mutex
}

// NewWriter returns a Writer for dir. The directory is created lazily, on the
// first write.
func NewWriter(dir string) *Writer {
	return &Writer{dir: dir}
}

// Dir returns the trail directory.
func (w *Writer) Dir() string {
	return w.dir
}

// Path returns the trail file path.
func (w *Writer) Path() string {
	return filepath.Join(w.dir, LogFileName)
}

// Write appends one record as a single JSON line.
//
// There is deliberately no fsync here: a record must survive the sops process
// dying (the kernel keeps written bytes), and the caller syncs once when the
// run finishes. That keeps the hot path to one open/write/close per file and
// avoids an fsync stall per file.
func (w *Writer) Write(record Record) error {
	if w.dir == "" {
		return fmt.Errorf("rotation log directory is empty")
	}
	record.normalize()
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("could not encode rotation record: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return fmt.Errorf("could not create rotation log directory: %w", err)
	}
	// O_APPEND makes the seek and the write one atomic step, so concurrent
	// sops runs append whole lines instead of interleaving halves.
	f, err := os.OpenFile(w.Path(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("could not open rotation log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("could not append rotation record: %w", err)
	}
	return nil
}

// Sync flushes the trail file to stable storage. Call once at the end of a run.
func (w *Writer) Sync() error {
	f, err := os.OpenFile(w.Path(), os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (r *Record) normalize() {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	if r.Timestamp == "" {
		r.Timestamp = Timestamp(time.Now())
	}
}

// RunWriter writes a run's records as they happen. A record that cannot be
// appended is remembered (in order) so it can be replayed later with Replay
// or spooled with WriteSpool.
type RunWriter struct {
	writer *Writer
	// pending holds records whose write failed, oldest first.
	pending []Record
	// written counts records successfully appended.
	written int
}

// NewRunWriter wraps writer.
func NewRunWriter(writer *Writer) *RunWriter {
	return &RunWriter{writer: writer}
}

// Write appends record. On failure the record is kept in Pending() and the
// error is returned; the caller warns and continues.
func (r *RunWriter) Write(record Record) error {
	record.normalize()
	if err := r.writer.Write(record); err != nil {
		r.pending = append(r.pending, record)
		return err
	}
	r.written++
	return nil
}

// Pending returns the records that could not be written, oldest first.
func (r *RunWriter) Pending() []Record {
	if len(r.pending) == 0 {
		return nil
	}
	out := make([]Record, len(r.pending))
	copy(out, r.pending)
	return out
}

// Written returns the number of records appended successfully.
func (r *RunWriter) Written() int {
	return r.written
}

// Sync flushes everything appended so far to stable storage.
func (r *RunWriter) Sync() error {
	return r.writer.Sync()
}

// Replay appends records that could not be written during the run.
func Replay(dir string, records []Record) (written int, err error) {
	w := NewWriter(dir)
	for i, record := range records {
		record.normalize()
		if err := w.Write(record); err != nil {
			return i, err
		}
		written++
	}
	if err := w.Sync(); err != nil {
		return written, err
	}
	return written, nil
}

// WriteSpool stores records in a standalone JSON Lines file that Replay (or
// `sops rotation-log append`) can consume later.
func WriteSpool(path string, records []Record) error {
	var buf bytes.Buffer
	for _, record := range records {
		record.normalize()
		line, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("could not encode rotation record: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// History is the per-file view produced by ReadFileHistory.
type History struct {
	File    string
	Entries []Record
}

// CorruptSpan describes one unreadable chunk of the trail.
type CorruptSpan struct {
	// Lines is the 1-based, inclusive line range that could not be decoded.
	Lines  string
	Reason string
}

// String renders the span the way it is printed to operators.
func (c CorruptSpan) String() string {
	return fmt.Sprintf("lines %s: %s", c.Lines, c.Reason)
}

// scan decodes a trail line by line. Good records are passed to keep; bad
// lines are folded into spans so the caller can report exactly which part of
// the trail is unreadable and therefore which entries may be missing.
func scan(path string, keep func(Record)) ([]CorruptSpan, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var spans []CorruptSpan
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	lineNo := 0
	spanStart := 0
	var spanReasons []string
	addReason := func(reason string) {
		for _, existing := range spanReasons {
			if existing == reason {
				return
			}
		}
		spanReasons = append(spanReasons, reason)
	}
	closeSpan := func(end int) {
		if spanStart != 0 {
			spans = append(spans, CorruptSpan{
				Lines:  fmt.Sprintf("%d-%d", spanStart, end),
				Reason: strings.Join(spanReasons, "; "),
			})
			spanStart = 0
			spanReasons = nil
		}
	}
	mark := func(reason string) {
		if spanStart == 0 {
			spanStart = lineNo
		}
		addReason(reason)
	}

	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			closeSpan(lineNo - 1)
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			mark("invalid JSON")
			continue
		}
		if record.SchemaVersion != SchemaVersion {
			mark(fmt.Sprintf("unsupported schema_version %d", record.SchemaVersion))
			continue
		}
		if record.Kind != KindFile && record.Kind != KindSummary {
			mark(fmt.Sprintf("unknown record kind %q", record.Kind))
			continue
		}
		closeSpan(lineNo - 1)
		keep(record)
	}
	if err := scanner.Err(); err != nil {
		closeSpan(lineNo)
		return spans, err
	}
	closeSpan(lineNo)
	return spans, nil
}

// ReadFileHistory returns every record for file, oldest first, together with
// the unreadable spans of the trail.
func ReadFileHistory(path, file string) (History, []CorruptSpan, error) {
	history := History{File: file}
	spans, err := scan(path, func(record Record) {
		if record.Kind == KindFile && record.File == file {
			history.Entries = append(history.Entries, record)
		}
	})
	return history, spans, err
}

// ReadRun returns all records belonging to rotationID, in file order.
func ReadRun(path, rotationID string) ([]Record, []CorruptSpan, error) {
	var records []Record
	spans, err := scan(path, func(record Record) {
		if record.RotationID == rotationID {
			records = append(records, record)
		}
	})
	return records, spans, err
}

// ReadAll returns every valid record in the trail.
func ReadAll(path string) ([]Record, []CorruptSpan, error) {
	var records []Record
	spans, err := scan(path, func(record Record) {
		records = append(records, record)
	})
	return records, spans, err
}

// Summarize folds file records into totals.
func Summarize(records []Record) Totals {
	var totals Totals
	for _, record := range records {
		if record.Kind != KindFile {
			continue
		}
		totals.Total++
		switch record.Status {
		case StatusSuccess:
			totals.Succeeded++
		case StatusSkipped:
			totals.Skipped++
		case StatusFailed:
			totals.Failed++
		}
	}
	return totals
}

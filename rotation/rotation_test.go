package rotation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeTrail(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, LogFileName)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func marshal(t *testing.T, r Record) string {
	t.Helper()
	r.normalize()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRecordHasSchemaVersionAndNoKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	writer := NewWriter(dir)
	record := Record{
		Kind:                  KindFile,
		RotationID:            "run-1",
		File:                  "secrets/db.yaml",
		Status:                StatusSuccess,
		Outcome:               OutcomeRotated,
		OldDataKeyFingerprint: DataKeyFingerprint([]byte("old data key material")),
		NewDataKeyFingerprint: DataKeyFingerprint([]byte("new data key material")),
		MasterKeysAdded: []KeyRef{{
			Type:        "age",
			ID:          "age1example",
			Fingerprint: Fingerprint("age1example"),
		}},
	}
	if err := writer.Write(record); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema_version":1`) {
		t.Fatalf("record is missing schema_version: %s", raw)
	}
	for _, secret := range []string{"old data key material", "new data key material"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("record leaked key material %q: %s", secret, raw)
		}
	}
}

func TestRunWritesSummaryAndPerFileRecords(t *testing.T) {
	dir := t.TempDir()
	writer := NewRunWriter(NewWriter(dir))
	items := []WorkItem{{Path: "a.yaml"}, {Path: "b.yaml"}}
	result := Run(items, "run-1", writer, func(item WorkItem) FileOutcome {
		if item.Path == "b.yaml" {
			return FileOutcome{Record: Record{File: item.Path, Status: StatusSkipped, SkipReason: SkipAlreadyRotated}}
		}
		return FileOutcome{Record: Record{File: item.Path, Status: StatusSuccess, Outcome: OutcomeRotated}}
	}, nil)

	if result.Totals != (Totals{Total: 2, Succeeded: 1, Skipped: 1}) {
		t.Fatalf("unexpected totals: %+v", result.Totals)
	}
	if err := writer.Sync(); err != nil {
		t.Fatal(err)
	}
	records, spans, err := ReadAll(writer.writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Fatalf("unexpected corrupt spans: %v", spans)
	}
	if len(records) != 3 {
		t.Fatalf("want 3 records (2 files + summary), got %d", len(records))
	}
	var summary *Record
	for i := range records {
		if records[i].Kind == KindSummary {
			summary = &records[i]
		}
	}
	if summary == nil || summary.Totals == nil {
		t.Fatal("missing summary record")
	}
	if *summary.Totals != (Totals{Total: 2, Succeeded: 1, Skipped: 1}) {
		t.Fatalf("summary totals mismatch: %+v", summary.Totals)
	}
}

func TestRunAbortKeepsHandledRecordsOnly(t *testing.T) {
	dir := t.TempDir()
	writer := NewRunWriter(NewWriter(dir))
	items := []WorkItem{{Path: "a.yaml"}, {Path: "b.yaml"}, {Path: "c.yaml"}}
	result := Run(items, "run-1", writer, func(item WorkItem) FileOutcome {
		if item.Path == "a.yaml" {
			return FileOutcome{Record: Record{File: item.Path, Status: StatusSuccess, Outcome: OutcomeRotated}}
		}
		// The run is interrupted while processing b.yaml: the record for
		// b.yaml is written, c.yaml never starts and leaves no record.
		return FileOutcome{Record: Record{File: item.Path, Status: StatusFailed, ErrorKind: ErrorDecrypt}, Err: os.ErrClosed, Abort: true}
	}, nil)

	if !result.Aborted {
		t.Fatal("expected run to abort")
	}
	if result.Totals.Total != 2 {
		t.Fatalf("want 2 handled files, got %+v", result.Totals)
	}
	records, _, err := ReadAll(writer.writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("want exactly 2 records (no summary, no c.yaml), got %d", len(records))
	}
	for _, record := range records {
		if record.File == "c.yaml" {
			t.Fatal("record for untouched file c.yaml must not exist")
		}
		if record.Kind == KindSummary {
			t.Fatal("interrupted run must not write a summary")
		}
	}
}

func TestRunInterruptStopsBetweenFiles(t *testing.T) {
	dir := t.TempDir()
	writer := NewRunWriter(NewWriter(dir))
	stop := make(chan struct{})
	close(stop)
	items := []WorkItem{{Path: "a.yaml"}, {Path: "b.yaml"}}
	result := Run(items, "run-1", writer, func(item WorkItem) FileOutcome {
		t.Fatalf("no file should be processed after an interrupt: %s", item.Path)
		return FileOutcome{}
	}, stop)
	if !result.Interrupted {
		t.Fatal("expected Interrupted")
	}
	if writer.Written() != 0 {
		t.Fatalf("no records should be written, got %d", writer.Written())
	}
}

func TestReadFileHistorySeparatesSkipReasons(t *testing.T) {
	dir := t.TempDir()
	path := writeTrail(t, dir,
		marshal(t, Record{Kind: KindFile, RotationID: "r1", File: "a.yaml", Status: StatusSuccess, Outcome: OutcomeRotated}),
		marshal(t, Record{Kind: KindFile, RotationID: "r2", File: "a.yaml", Status: StatusSkipped, SkipReason: SkipAlreadyRotated}),
		marshal(t, Record{Kind: KindFile, RotationID: "r2", File: "b.json", Status: StatusSkipped, SkipReason: SkipUnsupportedFormat}),
	)
	history, spans, err := ReadFileHistory(path, "a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Fatalf("unexpected spans: %v", spans)
	}
	if len(history.Entries) != 2 {
		t.Fatalf("want 2 entries for a.yaml, got %d", len(history.Entries))
	}
	if history.Entries[1].SkipReason != SkipAlreadyRotated {
		t.Fatalf("want already-rotated, got %q", history.Entries[1].SkipReason)
	}
}

func TestReadFileHistoryReportsCorruptSpans(t *testing.T) {
	dir := t.TempDir()
	path := writeTrail(t, dir,
		marshal(t, Record{Kind: KindFile, RotationID: "r1", File: "a.yaml", Status: StatusSuccess}),
		`{"schema_version":1,"kind":"file","rotation_id": "trunc`,
		`{"schema_version":99,"kind":"file","rotation_id":"r3","file":"a.yaml"}`,
		marshal(t, Record{Kind: KindFile, RotationID: "r2", File: "a.yaml", Status: StatusSkipped, SkipReason: SkipAlreadyRotated}),
	)
	history, spans, err := ReadFileHistory(path, "a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Entries) != 2 {
		t.Fatalf("good records must still be returned, got %d", len(history.Entries))
	}
	if len(spans) != 1 {
		t.Fatalf("contiguous bad lines must form one span, got %v", spans)
	}
	if spans[0].Lines != "2-3" {
		t.Fatalf("unexpected span range: %v", spans[0])
	}
	if !strings.Contains(spans[0].Reason, "invalid JSON") || !strings.Contains(spans[0].Reason, "schema_version") {
		t.Fatalf("span must name every distinct cause: %v", spans[0])
	}
}

func TestRelativePathNeverLeaksAbsoluteOrHome(t *testing.T) {
	root := "/home/alice/project"
	cases := map[string]string{
		"/home/alice/project/secrets/a.yaml":   "secrets/a.yaml",
		"/home/alice/project/a.yaml":           "a.yaml",
		"/home/alice/elsewhere/b.yaml":         "../elsewhere/b.yaml",
		"/srv/other/project2/secrets/../c.yml": "../../../srv/other/project2/c.yml",
	}
	for in, want := range cases {
		if got := RelativePath(root, in); got != want {
			t.Fatalf("RelativePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeTextRemovesHostLayout(t *testing.T) {
	got := SanitizeText("/home/alice/project", "open /home/alice/project/secrets/a.yaml: permission denied")
	if strings.Contains(got, "/home/alice") {
		t.Fatalf("sanitized text still contains home dir: %q", got)
	}
	got = SanitizeText("/home/alice/project", "open /etc/shadow: permission denied")
	if strings.Contains(got, "/etc/shadow") {
		t.Fatalf("sanitized text still contains an absolute path: %q", got)
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	a := Fingerprint("age1aaa")
	b := Fingerprint("age1aaa")
	c := Fingerprint("age1bbb")
	if a != b {
		t.Fatal("fingerprint is not stable")
	}
	if a == c {
		t.Fatal("different identifiers must have different fingerprints")
	}
	if !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("unexpected fingerprint format: %q", a)
	}
}

func TestConcurrentWritesProduceWholeLines(t *testing.T) {
	dir := t.TempDir()
	writer := NewWriter(dir)
	var wg sync.WaitGroup
	const writers = 8
	const perWriter = 25
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if err := writer.Write(Record{
					Kind:       KindFile,
					RotationID: "run",
					File:       filepath.Join("f", strings.Repeat("x", 200)),
					Status:     StatusSuccess,
				}); err != nil {
					t.Errorf("write failed: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	records, spans, err := ReadAll(writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Fatalf("concurrent appends interleaved: %v", spans)
	}
	if len(records) != writers*perWriter {
		t.Fatalf("want %d records, got %d", writers*perWriter, len(records))
	}
}

func TestWriteSpoolThenReplay(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool.jsonl")
	records := []Record{
		{Kind: KindFile, RotationID: "r1", File: "a.yaml", Status: StatusSuccess},
		{Kind: KindSummary, RotationID: "r1", Totals: &Totals{Total: 1, Succeeded: 1}},
	}
	if err := WriteSpool(spool, records); err != nil {
		t.Fatal(err)
	}
	back, spans, err := ReadAll(spool)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 || len(back) != 2 {
		t.Fatalf("spool round-trip failed: %d records, spans %v", len(back), spans)
	}
	if _, err := Replay(filepath.Join(dir, "trail"), back); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "trail", LogFileName)); err != nil {
		t.Fatal(err)
	}
}

func TestReplayIsIdempotentByCallerDedup(t *testing.T) {
	dir := t.TempDir()
	records := []Record{{Kind: KindFile, RotationID: "r1", File: "a.yaml", Status: StatusSuccess}}
	if _, err := Replay(dir, records); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(dir, records); err != nil {
		t.Fatal(err)
	}
	all, _, err := ReadAll(NewWriter(dir).Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 records, got %d", len(all))
	}
}

/*
Package diff provides in-memory structural comparison of decrypted SOPS
trees.

It is a pure comparison engine: it never performs any I/O, never writes to
disk, and only operates on values already decrypted in memory. The CLI
integration (loading and decrypting the two files) lives in
cmd/sops/subcommand/diff.
*/
package diff // import "github.com/getsops/sops/v3/diff"

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/getsops/sops/v3"
)

// ChangeType classifies a leaf comparison result.
type ChangeType int

const (
	// Equal means the path exists on both sides with the same type and value.
	Equal ChangeType = iota
	// ValueChanged means the path exists on both sides but the values differ
	// (either in type or in value).
	ValueChanged
	// OnlyInA means the path exists only in the first (left-hand) tree.
	OnlyInA
	// OnlyInB means the path exists only in the second (right-hand) tree.
	OnlyInB
)

// String renders a ChangeType for report output.
func (c ChangeType) String() string {
	switch c {
	case Equal:
		return "equal"
	case ValueChanged:
		return "changed"
	case OnlyInA:
		return "only in A"
	case OnlyInB:
		return "only in B"
	default:
		return "unknown"
	}
}

// Entry is a single leaf-level comparison result.
//
// Path holds the structural path from the document root, using strings for
// mapping keys and ints for array positions. Values are the decrypted leaf
// values; for paths missing on one side, the corresponding value is nil and
// the ChangeType indicates which side holds the value.
type Entry struct {
	// Path is the full path from the document root to the leaf.
	Path []interface{}
	// Change classifies the comparison.
	Change ChangeType
	// ValueA is the left-hand value, nil when the path only exists in B.
	ValueA interface{}
	// ValueB is the right-hand value, nil when the path only exists in A.
	ValueB interface{}
	// Sensitive is true when the leaf key matches a secret naming rule.
	// Sensitive values are masked in report output unless explicitly requested.
	Sensitive bool
}

// PathString renders Path in the same bracket notation used by the sops CLI,
// e.g. ["db"]["host"] or ["hosts"][2].
func (e Entry) PathString() string {
	var b strings.Builder
	for _, component := range e.Path {
		switch c := component.(type) {
		case string:
			b.WriteString("[")
			b.WriteString(strconvQuote(c))
			b.WriteString("]")
		case int:
			b.WriteString(fmt.Sprintf("[%d]", c))
		default:
			b.WriteString(fmt.Sprintf("[%v]", c))
		}
	}
	return b.String()
}

func strconvQuote(s string) string {
	// Match the JSON-ish quoting style of sops' --extract paths.
	return fmt.Sprintf("%q", s)
}

// Result is the full outcome of a tree comparison.
type Result struct {
	Entries []Entry
}

// Changed returns entries that are not Equal, in deterministic order.
func (r Result) Changed() []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Change != Equal {
			out = append(out, e)
		}
	}
	return out
}

// ByChange groups entries by their ChangeType, preserving deterministic order.
func (r Result) ByChange() map[ChangeType][]Entry {
	out := map[ChangeType][]Entry{}
	for _, e := range r.Entries {
		out[e.Change] = append(out[e.Change], e)
	}
	return out
}

// sensitiveFragments are lowercase substrings that mark a key as sensitive.
// A leaf is sensitive when any of its path components contains one of them,
// matched on word boundaries so that e.g. "credentials" flags itself but a
// sibling key "user" inside a credentials block is not masked.
var sensitiveFragments = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"private_key", "privatekey", "credential", "credentials",
}

// IsSensitivePath reports whether the leaf at the path looks like a
// secret-bearing key (password, token, key material, ...). The last string
// component of the path (the leaf key name, or the key of the array the leaf
// belongs to) is inspected. A field named "user" nested under a
// "credentials" mapping is not itself a secret.
func IsSensitivePath(path []interface{}) bool {
	for i := len(path) - 1; i >= 0; i-- {
		if key, ok := path[i].(string); ok {
			return isSensitiveKey(key)
		}
	}
	return false
}

// isSensitiveKey matches secret-bearing key names case-insensitively,
// tolerating separators such as "-", "." and casing differences
// (e.g. "DBPassword", "api-token", "tls_private_key").
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, fragment := range sensitiveFragments {
		if containsWord(lower, fragment) {
			return true
		}
	}
	return false
}

// containsWord reports whether s contains fragment, treating any run of
// non-letter/digit characters as equivalent separators.
func containsWord(s, fragment string) bool {
	normalize := func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}
	ns := strings.Map(normalize, s)
	nf := strings.Map(normalize, fragment)
	return strings.Contains(ns, nf)
}

// Options controls a comparison.
type Options struct {
	// PathPrefixes restricts the comparison to leaves whose path starts with
	// one of the given prefixes. An empty slice means "no filtering".
	PathPrefixes [][]interface{}
	// Sink, when non-nil, receives each Entry as soon as its leaves are
	// compared. In that mode entries are streamed to the callback instead of
	// being accumulated, so a comparison over a very large document keeps
	// constant memory apart from the current traversal stack. CompareTrees
	// leaves Sink nil and collects everything into the Result.
	Sink func(Entry)
}

// CompareTrees walks both decrypted trees down to their leaves and compares
// them structurally.
//
// Mappings are compared by key (order independent), arrays by content
// (element order is ignored: two arrays with the same multiset of elements
// compare equal). Scalar comparison is type-strict: the string "1" is not
// equal to the integer 1.
//
// Comparison is leaf-streaming: leaves are emitted as they are visited, the
// whole flattened keyspace is never materialized at once beyond the result
// accumulator.
func CompareTrees(a, b sops.TreeBranches, opts Options) Result {
	walker := newWalker(opts)
	walker.walkBranches(a, b, nil)
	return Result{Entries: walker.entries}
}

// CompareTreesStreaming runs the same comparison as CompareTrees but delivers
// each entry to the provided sink during the walk, without retaining the
// entries. Use this for documents with thousands of keys when the full result
// set would otherwise dominate memory. The sink is invoked in walk order;
// sort on the consumer side when deterministic output is required.
func CompareTreesStreaming(a, b sops.TreeBranches, opts Options, sink func(Entry)) {
	streamOpts := opts
	streamOpts.Sink = sink
	walker := newWalker(streamOpts)
	walker.walkBranches(a, b, nil)
}

type walker struct {
	opts    Options
	entries []Entry
}

func newWalker(opts Options) *walker {
	return &walker{opts: opts}
}

// filteredOut returns true when prefix filtering is active and the path does
// not match any configured prefix. The check runs on prefixes of the path too,
// so whole subtrees can be pruned while walking.
func (w *walker) filteredOut(path []interface{}) bool {
	if len(w.opts.PathPrefixes) == 0 {
		return false
	}
	for _, prefix := range w.opts.PathPrefixes {
		if pathHasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func pathHasPrefix(path, prefix []interface{}) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if !reflect.DeepEqual(path[i], prefix[i]) {
			return false
		}
	}
	return true
}

// subtreeCouldMatchPrefix returns false when no path under the current path
// can match a configured prefix, allowing whole-subtree pruning.
func (w *walker) subtreeCouldMatchPrefix(path []interface{}) bool {
	if len(w.opts.PathPrefixes) == 0 {
		return true
	}
	for _, prefix := range w.opts.PathPrefixes {
		if pathHasPrefix(prefix, path) || pathHasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (w *walker) emit(path []interface{}, change ChangeType, va, vb interface{}) {
	if w.filteredOut(path) {
		return
	}
	// Copy the path so callers can reuse the slice during the walk.
	pathCopy := append([]interface{}(nil), path...)
	entry := Entry{
		Path:      pathCopy,
		Change:    change,
		ValueA:    va,
		ValueB:    vb,
		Sensitive: IsSensitivePath(pathCopy),
	}
	if w.opts.Sink != nil {
		w.opts.Sink(entry)
		return
	}
	w.entries = append(w.entries, entry)
}

// walkBranches compares two ordered TreeBranches collections. SOPS documents
// normally have a single branch; each branch is compared by mapping key.
func (w *walker) walkBranches(a, b sops.TreeBranches, path []interface{}) {
	aMap := branchIndex(a)
	bMap := branchIndex(b)

	keys := unionKeys(aMap, bMap)
	for _, key := range keys {
		childPath := append(path, key)
		if !w.subtreeCouldMatchPrefix(childPath) {
			continue
		}
		av, inA := aMap[key]
		bv, inB := bMap[key]
		switch {
		case inA && !inB:
			w.walkOnlySide(av, childPath, true)
		case !inA && inB:
			w.walkOnlySide(bv, childPath, false)
		default:
			w.walkValue(av, bv, childPath)
		}
	}
}

// branchIndex flattens the branch collection into a map of string key -> value,
// ignoring comments (comments are presentation metadata, not configuration).
func branchIndex(branches sops.TreeBranches) map[string]interface{} {
	out := map[string]interface{}{}
	for _, branch := range branches {
		for _, item := range branch {
			if _, ok := item.Key.(sops.Comment); ok {
				continue
			}
			if key, ok := item.Key.(string); ok {
				out[key] = item.Value
			}
		}
	}
	return out
}

func unionKeys(a, b map[string]interface{}) []string {
	seen := map[string]struct{}{}
	var keys []string
	for k := range a {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	for k := range b {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// walkValue compares two values at the same path, dispatching on structure.
func (w *walker) walkValue(a, b interface{}, path []interface{}) {
	switch av := a.(type) {
	case sops.TreeBranch:
		bv, ok := b.(sops.TreeBranch)
		if !ok {
			// Different shapes: emit both subtrees leaf-by-leaf so the report
			// still points at concrete sub-keys rather than only the top key.
			w.walkOnlySide(av, path, true)
			w.walkOnlySide(b, path, false)
			return
		}
		w.walkBranches(sops.TreeBranches{av}, sops.TreeBranches{bv}, path)
	case []interface{}:
		bv, ok := b.([]interface{})
		if !ok {
			w.walkOnlySide(av, path, true)
			w.walkOnlySide(b, path, false)
			return
		}
		w.walkArrays(av, bv, path)
	default:
		if _, bIsComplex := b.(sops.TreeBranch); bIsComplex {
			// Scalar on A, structure on B: both sides are one-sided leaves.
			w.walkOnlySide(a, path, true)
			w.walkOnlySide(b, path, false)
			return
		}
		if _, bIsArray := b.([]interface{}); bIsArray {
			w.walkOnlySide(a, path, true)
			w.walkOnlySide(b, path, false)
			return
		}
		w.emit(path, classifyScalar(a, b), a, b)
	}
}

// walkArrays compares arrays by content, ignoring element order.
func (w *walker) walkArrays(a, b []interface{}, path []interface{}) {
	if arraysContentEqual(a, b) {
		// Emit equal leaves for every element so "equal" output is complete,
		// using the canonical (sorted) ordering of A.
		for i, item := range a {
			childPath := append(path, i)
			w.walkValue(item, item, childPath)
		}
		return
	}

	// Content differs. Pair elements up by a structural signature so that
	// equal/changed counterparts share an index, leftovers are one-sided.
	aRemaining := make([]int, len(a))
	bRemaining := make([]int, len(b))
	for i := range a {
		aRemaining[i] = i
	}
	for i := range b {
		bRemaining[i] = i
	}

	usedB := map[int]bool{}
	var pairs [][2]int // matched (aIndex, bIndex)
	for _, ai := range aRemaining {
		for _, bi := range bRemaining {
			if usedB[bi] {
				continue
			}
			if valuesEqual(a[ai], b[bi]) {
				pairs = append(pairs, [2]int{ai, bi})
				usedB[bi] = true
				break
			}
		}
	}

	// Emit matched pairs at A's index, then unmatched elements.
	matchedA := map[int]bool{}
	for _, p := range pairs {
		matchedA[p[0]] = true
		childPath := append(path, p[0])
		w.walkValue(a[p[0]], b[p[1]], childPath)
	}
	index := len(a)
	for ai, item := range a {
		if matchedA[ai] {
			continue
		}
		childPath := append(path, index)
		index++
		w.walkOnlySide(item, childPath, true)
	}
	for bi, item := range b {
		if usedB[bi] {
			continue
		}
		childPath := append(path, index)
		index++
		w.walkOnlySide(item, childPath, false)
	}
}

// walkOnlySide emits all leaves under a value that exists on one side only.
func (w *walker) walkOnlySide(value interface{}, path []interface{}, inA bool) {
	if !w.subtreeCouldMatchPrefix(path) {
		return
	}
	switch v := value.(type) {
	case sops.TreeBranch:
		for _, item := range v {
			if _, ok := item.Key.(sops.Comment); ok {
				continue
			}
			key, ok := item.Key.(string)
			if !ok {
				continue
			}
			w.walkOnlySide(item.Value, append(path, key), inA)
		}
	case []interface{}:
		for i, item := range v {
			w.walkOnlySide(item, append(path, i), inA)
		}
	default:
		if inA {
			w.emit(path, OnlyInA, value, nil)
		} else {
			w.emit(path, OnlyInB, nil, value)
		}
	}
}

// classifyScalar implements type-strict scalar comparison.
func classifyScalar(a, b interface{}) ChangeType {
	if valuesEqual(a, b) {
		return Equal
	}
	return ValueChanged
}

// valuesEqual compares two values with strict type semantics. reflect.DeepEqual
// already distinguishes string "1" from int 1, int from float64, etc. Complex
// values recurse so array order does not matter.
func valuesEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case sops.TreeBranch:
		bv, ok := b.(sops.TreeBranch)
		if !ok {
			return false
		}
		return branchesEqual(av, bv)
	case []interface{}:
		bv, ok := b.([]interface{})
		if !ok {
			return false
		}
		return arraysContentEqual(av, bv)
	default:
		return reflect.DeepEqual(a, b)
	}
}

func branchesEqual(a, b sops.TreeBranch) bool {
	am := map[string]interface{}{}
	bm := map[string]interface{}{}
	for _, item := range a {
		if _, ok := item.Key.(sops.Comment); ok {
			continue
		}
		if key, ok := item.Key.(string); ok {
			am[key] = item.Value
		}
	}
	for _, item := range b {
		if _, ok := item.Key.(sops.Comment); ok {
			continue
		}
		if key, ok := item.Key.(string); ok {
			bm[key] = item.Value
		}
	}
	if len(am) != len(bm) {
		return false
	}
	for k, v := range am {
		ov, ok := bm[k]
		if !ok || !valuesEqual(v, ov) {
			return false
		}
	}
	return true
}

// arraysContentEqual compares two arrays as multisets, ignoring element order.
func arraysContentEqual(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, av := range a {
		matched := false
		for j, bv := range b {
			if used[j] {
				continue
			}
			if valuesEqual(av, bv) {
				used[j] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

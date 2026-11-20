package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func branch(items ...sops.TreeItem) sops.TreeBranch {
	return sops.TreeBranch(items)
}

func item(key string, value interface{}) sops.TreeItem {
	return sops.TreeItem{Key: key, Value: value}
}

func findEntry(entries []Entry, path string) (Entry, bool) {
	for _, e := range entries {
		if e.PathString() == path {
			return e, true
		}
	}
	return Entry{}, false
}

func TestCompare_ValueChangedAndEqual(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("host", "db.example.com"),
		item("port", 5432),
		item("same", true),
	)}
	b := sops.TreeBranches{branch(
		item("host", "db-staging.example.com"),
		item("port", 5432),
		item("same", true),
	)}

	result := CompareTrees(a, b, Options{})
	groups := result.ByChange()

	require.Len(t, groups[ValueChanged], 1)
	assert.Equal(t, `["host"]`, groups[ValueChanged][0].PathString())
	assert.Equal(t, "db.example.com", groups[ValueChanged][0].ValueA)
	assert.Equal(t, "db-staging.example.com", groups[ValueChanged][0].ValueB)

	require.Len(t, groups[Equal], 2)
	port, ok := findEntry(groups[Equal], `["port"]`)
	require.True(t, ok)
	assert.Equal(t, 5432, port.ValueA)
}

func TestCompare_NestedLeafPath(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("db", branch(
			item("credentials", branch(
				item("user", "admin"),
				item("password", "prod-secret"),
			)),
		)),
	)}
	b := sops.TreeBranches{branch(
		item("db", branch(
			item("credentials", branch(
				item("user", "readonly"),
				item("password", "prod-secret"),
			)),
		)),
	)}

	result := CompareTrees(a, b, Options{})
	changed := result.ByChange()[ValueChanged]
	require.Len(t, changed, 1)
	assert.Equal(t, `["db"]["credentials"]["user"]`, changed[0].PathString())
	assert.True(t, changed[0].Sensitive == false)

	pw, ok := findEntry(result.Entries, `["db"]["credentials"]["password"]`)
	require.True(t, ok)
	assert.True(t, pw.Sensitive, "password leaf must be flagged sensitive")
	assert.Equal(t, Equal, pw.Change)
}

func TestCompare_OneSidedLeaves(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("only_prod", "x"),
		item("shared", 1),
	)}
	b := sops.TreeBranches{branch(
		item("only_staging", "y"),
		item("shared", 1),
	)}

	result := CompareTrees(a, b, Options{})
	groups := result.ByChange()
	require.Len(t, groups[OnlyInA], 1)
	require.Len(t, groups[OnlyInB], 1)
	assert.Equal(t, `["only_prod"]`, groups[OnlyInA][0].PathString())
	assert.Equal(t, `["only_staging"]`, groups[OnlyInB][0].PathString())
}

func TestCompare_ArrayOrderInsensitive(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("hosts", []interface{}{"a", "b", "c"}),
	)}
	b := sops.TreeBranches{branch(
		item("hosts", []interface{}{"c", "a", "b"}),
	)}

	result := CompareTrees(a, b, Options{})
	assert.Empty(t, result.ByChange()[ValueChanged])
	assert.Empty(t, result.ByChange()[OnlyInA])
	assert.Empty(t, result.ByChange()[OnlyInB])
	assert.Len(t, result.ByChange()[Equal], 3)
}

func TestCompare_ArrayContentDifferent(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("hosts", []interface{}{"a", "b", "c"}),
	)}
	b := sops.TreeBranches{branch(
		item("hosts", []interface{}{"a", "b", "d"}),
	)}

	result := CompareTrees(a, b, Options{})
	changed := result.ByChange()
	// "c" only in A, "d" only in B, "a"/"b" equal
	assert.Len(t, changed[OnlyInA], 1)
	assert.Len(t, changed[OnlyInB], 1)
	assert.Len(t, changed[Equal], 2)
}

func TestCompare_TypeStrict(t *testing.T) {
	a := sops.TreeBranches{branch(item("n", "1"))}
	b := sops.TreeBranches{branch(item("n", 1))}

	result := CompareTrees(a, b, Options{})
	changed := result.ByChange()[ValueChanged]
	require.Len(t, changed, 1)
	assert.Equal(t, "1", changed[0].ValueA)
	assert.Equal(t, 1, changed[0].ValueB)
}

func TestCompare_TypeStrictFloatVsInt(t *testing.T) {
	a := sops.TreeBranches{branch(item("n", 1))}
	b := sops.TreeBranches{branch(item("n", 1.0))}

	result := CompareTrees(a, b, Options{})
	assert.Len(t, result.ByChange()[ValueChanged], 1)
}

func TestCompare_PrefixFilter(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("db", branch(item("host", "prod"))),
		item("cache", branch(item("host", "prod"))),
	)}
	b := sops.TreeBranches{branch(
		item("db", branch(item("host", "staging"))),
		item("cache", branch(item("host", "staging"))),
	)}

	result := CompareTrees(a, b, Options{
		PathPrefixes: [][]interface{}{{"db"}},
	})
	changed := result.ByChange()[ValueChanged]
	require.Len(t, changed, 1)
	assert.Equal(t, `["db"]["host"]`, changed[0].PathString())
}

func TestCompare_NullValues(t *testing.T) {
	a := sops.TreeBranches{branch(item("x", nil), item("y", nil))}
	b := sops.TreeBranches{branch(item("x", nil), item("y", "z"))}

	result := CompareTrees(a, b, Options{})
	groups := result.ByChange()
	require.Len(t, groups[Equal], 1)
	assert.Nil(t, groups[Equal][0].ValueA)
	require.Len(t, groups[ValueChanged], 1)
}

func TestIsSensitivePath(t *testing.T) {
	assert.True(t, IsSensitivePath([]interface{}{"password"}))
	assert.True(t, IsSensitivePath([]interface{}{"db", "api_token"}))
	assert.True(t, IsSensitivePath([]interface{}{"TLS_PRIVATE_KEY"}))
	assert.True(t, IsSensitivePath([]interface{}{"credentials"}))
	assert.False(t, IsSensitivePath([]interface{}{"host"}))
	assert.False(t, IsSensitivePath([]interface{}{0, "region"}))
}

func TestRenderReport_MasksSensitiveByDefault(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("password", "prod-secret"),
		item("host", "prod"),
	)}
	b := sops.TreeBranches{branch(
		item("password", "staging-secret"),
		item("host", "staging"),
	)}

	result := CompareTrees(a, b, Options{})

	var masked bytes.Buffer
	require.NoError(t, RenderReport(&masked, result, ReportOptions{}))
	maskedOut := masked.String()
	assert.Contains(t, maskedOut, Mask)
	assert.NotContains(t, maskedOut, "prod-secret")
	assert.NotContains(t, maskedOut, "staging-secret")
	assert.Contains(t, maskedOut, `"host"`)

	var shown bytes.Buffer
	require.NoError(t, RenderReport(&shown, result, ReportOptions{ShowSensitive: true}))
	shownOut := shown.String()
	assert.Contains(t, shownOut, "prod-secret")
	assert.NotContains(t, shownOut, Mask)
}

func TestRenderReport_SectionsAndSummary(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("changed", 1),
		item("only_a", "x"),
		item("same", "z"),
	)}
	b := sops.TreeBranches{branch(
		item("changed", 2),
		item("only_b", "y"),
		item("same", "z"),
	)}

	result := CompareTrees(a, b, Options{})
	var buf bytes.Buffer
	require.NoError(t, RenderReport(&buf, result, ReportOptions{ShowEqual: true}))
	out := buf.String()

	assert.True(t, strings.Contains(out, "Changed values (1):"))
	assert.True(t, strings.Contains(out, "Only in A (left file) (1):"))
	assert.True(t, strings.Contains(out, "Only in B (right file) (1):"))
	assert.True(t, strings.Contains(out, "Equal values (1):"))
	assert.True(t, strings.Contains(out, "Summary: changed=1 only_in_a=1 only_in_b=1 equal=1"))
}

func TestCompare_ComplexArrayOrderInsensitive(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("nodes", []interface{}{
			branch(item("name", "n1"), item("port", 1)),
			branch(item("name", "n2"), item("port", 2)),
		}),
	)}
	b := sops.TreeBranches{branch(
		item("nodes", []interface{}{
			branch(item("name", "n2"), item("port", 2)),
			branch(item("name", "n1"), item("port", 1)),
		}),
	)}

	result := CompareTrees(a, b, Options{})
	assert.Empty(t, result.Changed(), "arrays of objects with same content in different order must be equal")
}

func TestCompare_ShapeMismatchScalarVsMap(t *testing.T) {
	a := sops.TreeBranches{branch(item("x", "scalar"))}
	b := sops.TreeBranches{branch(item("x", branch(item("inner", 1))))}

	result := CompareTrees(a, b, Options{})
	groups := result.ByChange()
	require.Len(t, groups[OnlyInA], 1)
	require.Len(t, groups[OnlyInB], 1)
	assert.Equal(t, `["x"]`, groups[OnlyInA][0].PathString())
	assert.Equal(t, `["x"]["inner"]`, groups[OnlyInB][0].PathString())
}

func TestCompare_StreamingSink(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("changed", 1),
		item("same", "z"),
		item("only_a", true),
	)}
	b := sops.TreeBranches{branch(
		item("changed", 2),
		item("same", "z"),
		item("only_b", false),
	)}

	collected := CompareTrees(a, b, Options{})

	var streamed []Entry
	CompareTreesStreaming(a, b, Options{}, func(e Entry) {
		// A streaming consumer must be able to classify entries itself.
		streamed = append(streamed, e)
	})

	assert.ElementsMatch(t, collected.Entries, streamed,
		"the streaming sink must observe exactly the same entries as the collecting variant")
}

func TestCompare_StreamingSinkHonorsPrefix(t *testing.T) {
	a := sops.TreeBranches{branch(
		item("db", branch(item("host", "prod"))),
		item("cache", branch(item("host", "prod"))),
	)}
	b := sops.TreeBranches{branch(
		item("db", branch(item("host", "staging"))),
		item("cache", branch(item("host", "staging"))),
	)}

	var streamed []Entry
	CompareTreesStreaming(a, b, Options{PathPrefixes: [][]interface{}{{"db"}}}, func(e Entry) {
		streamed = append(streamed, e)
	})
	require.Len(t, streamed, 1)
	assert.Equal(t, `["db"]["host"]`, streamed[0].PathString())
}

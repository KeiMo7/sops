//go:build !windows

package atomic

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

func assertOwnerUnchanged(t *testing.T, before, after os.FileInfo) {
	t.Helper()
	b, ok1 := before.Sys().(*syscall.Stat_t)
	a, ok2 := after.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		t.Skip("platform stat type unavailable")
	}
	assert.Equal(t, b.Uid, a.Uid, "uid must be preserved")
	assert.Equal(t, b.Gid, a.Gid, "gid must be preserved")
}

//go:build linux || darwin || dragonfly || freebsd

package atomic

import "golang.org/x/sys/unix"

// statfsAvailable returns the free bytes usable by an unprivileged user.
func statfsAvailable(st *unix.Statfs_t) int64 {
	return int64(st.Bavail) * int64(st.Bsize)
}

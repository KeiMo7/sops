//go:build openbsd

package atomic

import "golang.org/x/sys/unix"

// On OpenBSD the Statfs_t fields are named F_bavail and F_bsize.
func statfsAvailable(st *unix.Statfs_t) int64 {
	return int64(st.F_bavail) * int64(st.F_bsize)
}

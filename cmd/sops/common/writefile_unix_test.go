//go:build unix

package common

import "syscall"

func setUmask(mask int) func() {
	old := syscall.Umask(mask)
	return func() { syscall.Umask(old) }
}

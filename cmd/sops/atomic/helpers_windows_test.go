//go:build windows

package atomic

import "os"

func inodeOf(info os.FileInfo) uint64 { return 0 }

func assertOwnerUnchanged(t interface{ Helper() }, before, after os.FileInfo) {}

//go:build !windows

package control

import "os"

func readStateFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// replaceStateFile: rename(2) already replaces the name atomically while readers hold the old file.
func replaceStateFile(tmp, path string) error {
	return os.Rename(tmp, path)
}

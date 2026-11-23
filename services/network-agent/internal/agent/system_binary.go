package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

var systemBinaryDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

func findSystemBinary(name string) (string, error) {
	return findExecutable(name, systemBinaryDirs)
}

func findExecutable(name string, dirs []string) (string, error) {
	for _, dir := range dirs {
		path := filepath.Join(dir, name)

		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}

	return "", fmt.Errorf("system %s executable not found", name)
}

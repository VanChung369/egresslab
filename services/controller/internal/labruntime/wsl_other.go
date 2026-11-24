//go:build !windows

package labruntime

import "errors"

func newWSL(string) (launcher, error) {
	return nil, errors.New("the WSL runtime requires Windows")
}

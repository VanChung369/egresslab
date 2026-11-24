//go:build !linux

package labruntime

import "errors"

func newNative() (launcher, error) {
	return nil, errors.New("the native runtime requires a Linux host")
}

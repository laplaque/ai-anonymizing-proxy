//go:build !windows

package main

import "errors"

// removeCAFromStore is implemented only on Windows. The flag is rejected
// at the CLI level on every other platform so an MSI custom action that
// somehow ends up on a non-Windows binary fails loudly rather than
// silently leaving CA state behind.
func removeCAFromStore(_ string) error {
	return errors.New("--remove-ca-from-store is only supported on Windows")
}

package main

// A write to a closed pipe already fails with an error on Windows.
func reportBrokenStdout() {}

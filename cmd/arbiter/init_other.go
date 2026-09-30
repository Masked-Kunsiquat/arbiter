//go:build !windows

package main

// printDevDriveRecommendation is a no-op on non-Windows platforms.
func printDevDriveRecommendation(_ string) {}

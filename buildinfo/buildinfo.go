// Package buildinfo carries version information stamped at build time.
//
// The default is "dev". Release builds override it with the git tag via the
// linker, e.g.
//
//	go build -ldflags "-X github.com/salehkreiner/netherchat/buildinfo.Version=1.2.0"
//
// Both binaries and the Docker image and GoReleaser target this single symbol,
// so there is exactly one place a version comes from.
package buildinfo

// Version is the Netherchat version. Overridden at link time for releases.
var Version = "dev"

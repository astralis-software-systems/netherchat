// Package buildinfo carries version information stamped at build time.
//
// The default is "dev". Release builds override it with the git tag via the
// linker, e.g.
//
//	go build -ldflags "-X github.com/salehkreiner/netherchat/buildinfo.Version=X.Y.Z"
//
// Both binaries and the Docker image and GoReleaser target this single symbol,
// so there is exactly one place a version comes from.
package buildinfo

// Version is the Netherchat version. Overridden at link time for releases.
var Version = "dev"

// SourceURL is where the Corresponding Source for this build can be obtained,
// as AGPL-3.0 §13 requires for network-interactive use. Operators running a
// MODIFIED Netherchat must override this to point at their own source, the
// same way Version is overridden.
var SourceURL = "https://github.com/salehkreiner/netherchat"

// License is the SPDX identifier this build is distributed under.
var License = "AGPL-3.0-or-later"

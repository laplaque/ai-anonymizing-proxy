// Package config loads and holds all proxy configuration.
// Settings are layered: defaults → proxy-config.json → environment variables (env vars win).
// Upstream proxy chaining is configured via the UpstreamProxy field / UPSTREAM_PROXY env var.
package config

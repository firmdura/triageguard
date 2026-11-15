module github.com/firmdura/triageguard

go 1.27.0

toolchain go1.27.4

require go.yaml.in/yaml/v3 v3.0.4

// Pre-stable releases are retired; use v1.0.0 or later.
retract [v0.1.0, v0.1.1]

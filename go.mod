// File    : go.mod
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Module definition for dns-good.
//          Run "go mod tidy" after cloning to pull indirect deps and
//          generate go.sum. Three direct dependencies:
//            github.com/miekg/dns  — iterative DNS resolution
//            modernc.org/sqlite    — pure-Go SQLite (no CGO required)
//            gopkg.in/yaml.v3      — config file parsing

module dns-good

go 1.25.0

require (
	github.com/miekg/dns v1.1.72
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.48.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

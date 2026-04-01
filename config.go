// File    : config.go
// Version : 1.0.0
// Modified: 2026-04-01 12:00 UTC
//
// Changes:
//   v1.0.0 - 2026-04-01 - Initial implementation
//
// Summary: Configuration struct and YAML loader. A missing config
//          file is not an error — all fields have sensible defaults.
//          Partial YAML files are merged on top of those defaults.

package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds every tunable for dns-good. Field docs are in config.yaml.
type Config struct {
	DB struct {
		Path string `yaml:"path"`
	} `yaml:"db"`

	Validation struct {
		Workers         int           `yaml:"workers"`
		StaleTTL        time.Duration `yaml:"stale_ttl"`
		RevalidateDelay time.Duration `yaml:"revalidate_delay"`
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"validation"`

	DNS struct {
		RootServers []string      `yaml:"root_servers"`
		MaxDepth    int           `yaml:"max_depth"`
		Retries     int           `yaml:"retries"`
		Timeout     time.Duration `yaml:"timeout"`
	} `yaml:"dns"`

	RDAP struct {
		BootstrapURL string        `yaml:"bootstrap_url"`
		CachePath    string        `yaml:"cache_path"`
		CacheTTL     time.Duration `yaml:"cache_ttl"`
		Timeout      time.Duration `yaml:"timeout"`
		MinGapMs     int           `yaml:"min_gap_ms"` // ms between requests to the same RDAP host
	} `yaml:"rdap"`

	TopN struct {
		Provider   string        `yaml:"provider"`
		URL        string        `yaml:"url"`
		CachePath  string        `yaml:"cache_path"`
		RefreshTTL time.Duration `yaml:"refresh_ttl"`
		Size       int           `yaml:"size"`
	} `yaml:"topn"`
}

// newDefaultConfig returns a fully populated Config with production-ready defaults.
// Every field here has a matching entry (and explanation) in config.yaml.
func newDefaultConfig() *Config {
	c := &Config{}

	c.DB.Path = "dns-good.db"

	c.Validation.Workers = 20
	c.Validation.StaleTTL = 24 * time.Hour
	c.Validation.RevalidateDelay = 4 * time.Hour
	c.Validation.Timeout = 15 * time.Second

	// All 13 IANA root servers. We pick one at random per resolution
	// to spread load naturally across the anycast clusters.
	c.DNS.RootServers = []string{
		"198.41.0.4",     // a.root-servers.net
		"170.247.170.2",  // b.root-servers.net
		"192.33.4.12",    // c.root-servers.net
		"199.7.91.13",    // d.root-servers.net
		"192.203.230.10", // e.root-servers.net
		"192.5.5.241",    // f.root-servers.net
		"192.112.36.4",   // g.root-servers.net
		"198.97.190.53",  // h.root-servers.net
		"192.36.148.17",  // i.root-servers.net
		"192.58.128.30",  // j.root-servers.net
		"193.0.14.129",   // k.root-servers.net
		"199.7.83.42",    // l.root-servers.net
		"202.12.27.33",   // m.root-servers.net
	}
	c.DNS.MaxDepth = 12
	c.DNS.Retries = 2
	c.DNS.Timeout = 5 * time.Second

	c.RDAP.BootstrapURL = "https://data.iana.org/rdap/dns.json"
	c.RDAP.CachePath = "rdap-bootstrap.json"
	c.RDAP.CacheTTL = 48 * time.Hour
	c.RDAP.Timeout = 10 * time.Second
	c.RDAP.MinGapMs = 500 // ~2 req/s per RDAP host

	c.TopN.Provider = "tranco"
	c.TopN.URL = "https://tranco-list.eu/top-1m.csv.zip"
	c.TopN.CachePath = "tranco.csv"
	c.TopN.RefreshTTL = 24 * time.Hour
	c.TopN.Size = 1_000_000

	return c
}

// LoadConfig loads a YAML config from path and merges it onto the defaults.
// If path is empty or the file doesn't exist, pure defaults are returned.
func LoadConfig(path string) (*Config, error) {
	cfg := newDefaultConfig()
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no config file is perfectly fine
		}
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}


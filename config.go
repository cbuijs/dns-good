// File    : config.go
// Version : 1.5.0
// Modified: 2026-04-01 18:15 UTC
//
// Changes:
//   v1.5.0 - 2026-04-01 - Standardised file header
//   v1.4.0 - 2026-04-01 - Added RootZone config section
//   v1.3.0 - 2026-04-01 - Added RDAP.ThrottleBackoff (default 5m)
//   v1.2.0 - 2026-04-01 - Added MinActiveScore (default 100)
//   v1.1.0 - 2026-04-01 - Added Output.Dir
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

type Config struct {
	DB struct {
		Path string `yaml:"path"`
	} `yaml:"db"`

	Validation struct {
		Workers         int           `yaml:"workers"`
		StaleTTL        time.Duration `yaml:"stale_ttl"`
		RevalidateDelay time.Duration `yaml:"revalidate_delay"`
		Timeout         time.Duration `yaml:"timeout"`
		MinActiveScore  int           `yaml:"min_active_score"`
	} `yaml:"validation"`

	DNS struct {
		RootServers []string      `yaml:"root_servers"`
		MaxDepth    int           `yaml:"max_depth"`
		Retries     int           `yaml:"retries"`
		Timeout     time.Duration `yaml:"timeout"`
	} `yaml:"dns"`

	RDAP struct {
		BootstrapURL    string        `yaml:"bootstrap_url"`
		CachePath       string        `yaml:"cache_path"`
		CacheTTL        time.Duration `yaml:"cache_ttl"`
		Timeout         time.Duration `yaml:"timeout"`
		MinGapMs        int           `yaml:"min_gap_ms"`
		ThrottleBackoff time.Duration `yaml:"throttle_backoff"`
	} `yaml:"rdap"`

	RootZone struct {
		Enabled    bool          `yaml:"enabled"`
		URL        string        `yaml:"url"`
		CachePath  string        `yaml:"cache_path"`
		RefreshTTL time.Duration `yaml:"refresh_ttl"`
	} `yaml:"rootzone"`

	Output struct {
		Dir string `yaml:"dir"`
	} `yaml:"output"`

	TopN struct {
		Provider   string        `yaml:"provider"`
		URL        string        `yaml:"url"`
		CachePath  string        `yaml:"cache_path"`
		RefreshTTL time.Duration `yaml:"refresh_ttl"`
		Size       int           `yaml:"size"`
	} `yaml:"topn"`
}

func newDefaultConfig() *Config {
	c := &Config{}

	c.DB.Path = "dns-good.db"

	c.Validation.Workers         = 20
	c.Validation.StaleTTL        = 24 * time.Hour
	c.Validation.RevalidateDelay = 4 * time.Hour
	c.Validation.Timeout         = 15 * time.Second
	c.Validation.MinActiveScore  = 100

	c.DNS.RootServers = []string{
		"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
		"192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
		"192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
		"202.12.27.33",
	}
	c.DNS.MaxDepth = 12
	c.DNS.Retries  = 2
	c.DNS.Timeout  = 5 * time.Second

	c.RDAP.BootstrapURL    = "https://data.iana.org/rdap/dns.json"
	c.RDAP.CachePath       = "rdap-bootstrap.json"
	c.RDAP.CacheTTL        = 48 * time.Hour
	c.RDAP.Timeout         = 10 * time.Second
	c.RDAP.MinGapMs        = 500
	c.RDAP.ThrottleBackoff = 5 * time.Minute

	c.RootZone.Enabled    = true
	c.RootZone.URL        = "https://www.internic.net/domain/root.zone"
	c.RootZone.CachePath  = "root.zone"
	c.RootZone.RefreshTTL = 24 * time.Hour

	c.Output.Dir = "output"

	c.TopN.Provider   = "tranco"
	c.TopN.URL        = "https://tranco-list.eu/top-1m.csv.zip"
	c.TopN.CachePath  = "tranco.csv"
	c.TopN.RefreshTTL = 24 * time.Hour
	c.TopN.Size       = 1_000_000

	return c
}

func LoadConfig(path string) (*Config, error) {
	cfg := newDefaultConfig()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}


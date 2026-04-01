# dns-good

A self-contained DNS domain validation engine with a persistent repository.
It cross-references multiple data sources to determine whether a domain is
genuinely active, and keeps that knowledge fresh over time without hammering
any single external service.

---

## What it does

dns-good maintains a SQLite repository of domain names. Each entry gets a
**trust score** (0–250) derived from up to four independent sources:

| Source | Points | What it means |
|---|---|---|
| TOP-N list (Tranco) | 50 | Apex domain appears in a well-known popularity ranking |
| RDAP / registration | 50 | The registry reports the domain as actively registered |
| DNS delegation | 50 | NS records exist — the zone is delegated |
| DNS resolution | 100 | The apex resolves to at least one A or AAAA address |

A domain with **any score > 0** is marked `ACTIVE`. Zero evidence → `INACTIVE`.
Entries age into `STALE` after a configurable TTL and are automatically
revalidated on the next run.

### Why iterative DNS?

dns-good walks the DNS delegation chain itself — root → TLD → authoritative NS —
instead of forwarding queries to a shared recursive resolver. This means:

- No throttling by public resolvers under high volume.
- Full visibility into the delegation path (NS records, glue, NXDOMAIN).
- Load is spread across all 13 IANA root server anycast clusters.

The only exception is resolving **NS hostnames** when no glue records are
present. Those use a public resolver as a pragmatic fallback — doing full
iterative resolution for NS infrastructure too would create deep recursive
chains for negligible accuracy gain.

---

## Repository entry fields

| Field | Description |
|---|---|
| `domain` | Full domain name as submitted |
| `apex` | Registered apex (e.g. `example.com` for `sub.example.com`) |
| `status` | `ACTIVE` / `INACTIVE` / `STALE` / `UNKNOWN` |
| `score` | Trust score 0–250 |
| `first_seen` | Timestamp of the very first successful validation |
| `last_active` | Most recent timestamp where score was > 0 |
| `last_checked` | Timestamp of the last validation attempt |
| `sources` | Which sources confirmed activity on the last check |

---

## Build

Requires **Go 1.22+**. No CGO — the SQLite driver is pure Go.

```bash
git clone https://github.com/your-org/dns-good
cd dns-good
go mod tidy        # pulls github.com/miekg/dns, modernc.org/sqlite, gopkg.in/yaml.v3
go build -o dns-good .
```

---

## Usage

```
./dns-good [flags]

Flags:
  -config  string   Path to YAML config file     (default: config.yaml)
  -mode    string   Run mode: check | run | stats (default: check)
  -input   string   File with one domain per line (check/run mode)
  -workers int      Override worker count from config (0 = use config)
```

### Modes

#### `check` — one-shot validation

Reads domains from `-input`, adds any new ones to the repository, validates
all `UNKNOWN` and `STALE` entries, writes results, and exits. Ideal for
cron jobs or pipeline use.

```bash
# Validate a list of domains once
./dns-good -mode check -input domains.txt

# Pipe domains directly from stdin
cat domains.txt | ./dns-good -mode check
```

#### `run` — continuous daemon

Same as `check` but loops indefinitely. After each pass it sleeps for
`revalidate_delay`, marks old entries as `STALE`, and repeats. Handles
`SIGINT` / `SIGTERM` for a clean shutdown.

```bash
# Run as a daemon; feed it a fresh list each cycle
./dns-good -mode run -input domains.txt

# Run without an input file — only revalidates existing stale entries
./dns-good -mode run
```

#### `stats` — repository summary

Prints a per-status domain count from the repository and exits.

```bash
./dns-good -mode stats

# Example output:
# dns-good repository statistics
# -------------------------------
#   ACTIVE     48231
#   INACTIVE    3104
#   STALE        812
#   UNKNOWN       57
#   TOTAL      52204
```

---

## Input file format

One domain per line. Lines starting with `#` and blank lines are ignored.
Both apex domains and subdomains are accepted — subdomains are normalised
to their apex for RDAP and TOP-N lookups.

```
# Top sites
google.com
github.com
sub.example.co.uk
# this line is ignored
```

---

## Configuration

Copy `config.yaml` and adjust as needed. Every field has a built-in default,
so a partial file (or no file at all) is fine.

```yaml
db:
  path: dns-good.db         # SQLite file; created automatically

validation:
  workers: 20               # Parallel validation goroutines
  stale_ttl: 24h            # Entries older than this become STALE
  revalidate_delay: 4h      # Sleep between cycles in run mode
  timeout: 15s              # Hard per-domain deadline

dns:
  max_depth: 12             # Max NS referral hops before failure
  retries: 2                # UDP retries per nameserver
  timeout: 5s               # Per-query timeout (TCP gets 2×)

rdap:
  min_gap_ms: 500           # Min ms between requests to the same RDAP host
  cache_ttl: 48h            # How long to keep the IANA bootstrap cache

topn:
  provider: tranco
  size: 1000000             # Load top-N entries (lower = less memory)
  refresh_ttl: 24h          # Re-download the list after this period
```

> **Tuning tip:** lower `workers` if you hit RDAP rate limits; the built-in
> per-host gap (`min_gap_ms`) already throttles RDAP to ~2 req/s per registry,
> but busy registries may need a higher value.

---

## Files

| File | Purpose |
|---|---|
| `main.go` | Entry point, CLI flags, mode dispatch |
| `types.go` | Shared types, status constants, score weights |
| `config.go` | Config struct, YAML loader, defaults |
| `config.yaml` | Runtime configuration |
| `store.go` | SQLite repository (upsert, stale marking, queries) |
| `resolver.go` | Iterative DNS resolver (root → TLD → auth NS) |
| `rdap.go` | RDAP client with IANA bootstrap and per-host rate limiting |
| `topn.go` | Tranco TOP-N list downloader and in-memory rank lookup |
| `scorer.go` | Trust score calculation and status assignment |
| `validator.go` | Worker pool, per-domain orchestration, deadline enforcement |

---


# dns-good

A self-contained DNS domain validation engine with a persistent repository.
It cross-references multiple data sources to determine whether a domain is
genuinely active, and keeps that knowledge fresh over time without hammering
any single external service.

---

## What it does

dns-good maintains a SQLite repository of domain names. Each entry gets a
**trust score** (0–250) built up from up to four independent sources, and a
**status** that reflects whether the domain is considered live right now.

---

### Trust score

| Source | Points | What it checks |
|---|---|---|
| TOP-N list (Tranco) | +50 | Apex domain appears in a well-known popularity ranking |
| RDAP / registration | +50 | The registry reports the domain as actively registered |
| DNS delegation | +50 | NS records exist — the zone is delegated to a nameserver |
| DNS resolution | +100 | The apex resolves to at least one A or AAAA address |

The higher the score, the more independent sources agree the domain is real and
operational. A score of 250 means all four checks passed.

---

### Status

Status is **not** simply "score > 0". TOP-N and RDAP are backward-looking
sources — a domain can still be on a popularity list or show as registered days
after going dark. Two conditions must both be true for a domain to be `ACTIVE`:

1. **Score ≥ `min_active_score`** (configurable, default **100**)
2. **Live DNS evidence** — NS records or an A/AAAA answer must exist

| Score | NS or A/AAAA found? | Status |
|---|---|---|
| ≥ min_active_score | yes | `ACTIVE` |
| ≥ min_active_score | no | `INACTIVE` |
| < min_active_score | anything | `INACTIVE` |

Practical examples at the default threshold of 100:

| What the checks found | Score | Status | Why |
|---|---|---|---|
| TOP-N only | 50 | `INACTIVE` | No DNS evidence |
| RDAP active only | 50 | `INACTIVE` | No DNS evidence |
| NS records only | 50 | `INACTIVE` | Below threshold |
| TOP-N + NS | 100 | `ACTIVE` | Threshold met, DNS confirmed |
| RDAP + NS | 100 | `ACTIVE` | Threshold met, DNS confirmed |
| A/AAAA only | 100 | `ACTIVE` | Threshold met by resolution alone |
| TOP-N + RDAP + NS | 150 | `ACTIVE` | Two sources + delegation |
| All four | 250 | `ACTIVE` | Maximum confidence |

Configure the threshold to taste:

```yaml
validation:
  min_active_score: 100   # default — DNS resolution alone is sufficient
  # min_active_score: 50  # lenient — NS records alone qualifies
  # min_active_score: 150 # strict  — delegation + 2 other sources required
  # min_active_score: 250 # paranoid — all four sources must confirm
```

---

### Lifecycle

Entries move through four states:

```
UNKNOWN ──(first check)──► ACTIVE or INACTIVE
                                │
                          (stale_ttl elapsed)
                                │
                             STALE
                                │
                          (next run picks up)
                                │
                        ACTIVE or INACTIVE
```

| Status | Meaning |
|---|---|
| `UNKNOWN` | Queued from input, never checked yet |
| `ACTIVE` | Score > 0 and live DNS evidence on last check |
| `INACTIVE` | No DNS evidence (or zero score) on last check |
| `STALE` | Last check is older than `stale_ttl` — awaiting revalidation |

`STALE` is a **time-driven transition**, not a check result. dns-good marks
`ACTIVE` and `INACTIVE` entries stale automatically so they get rechecked
periodically without any manual intervention.

---

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
| `status` | `ACTIVE` / `INACTIVE` / `STALE` / `UNKNOWN` — see above |
| `score` | Trust score 0–250 — how many sources confirmed activity |
| `first_seen` | Timestamp of the very first successful validation |
| `last_active` | Most recent timestamp where status was `ACTIVE` |
| `last_checked` | Timestamp of the last validation attempt (any outcome) |
| `sources` | Which sources confirmed activity on the last check |

## Output files

After every `check` or `run` cycle dns-good writes one plain-text file per
status into the configured output directory. The files are always a complete
snapshot of the repository at that moment — not a diff or delta.

```
output/
  active.txt
  inactive.txt
  stale.txt
  unknown.txt
```

Each file has a small self-describing header followed by one domain per line,
sorted alphabetically:

```
# dns-good — ACTIVE domains
# Generated : 2026-04-01T14:32:07Z
# Count     : 48231
# Score note: score > 0 — at least one source confirmed activity
#
example.com
github.com
google.com
...
```

A few details worth knowing:

- **Always written** — export runs at the end of every cycle regardless of
  whether any validation work was done. The files always reflect current store
  state, not just what changed this run.
- **Atomic writes** — each file is written to a `.tmp` sibling first, then
  renamed into place. Readers never see a partial file mid-update.
- **Disabled by default when `dir` is empty** — set `output.dir: ""` in
  `config.yaml` to turn off file export entirely (the SQLite store is still
  updated as normal).

Configure the output directory in `config.yaml`:

```yaml
output:
  dir: output    # relative or absolute path; created automatically if absent
                 # set to "" to disable
```

Or point it elsewhere at runtime — the directory is created if it doesn't exist:

```yaml
output:
  dir: /var/lib/dns-good/lists
```

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

### Starting fresh

Use `-reset` to wipe the database and output directory before a run. This is a
hard reset — all previous results are gone.

```bash
# Start from scratch, then immediately check a new list
./dns-good -reset -mode check -input domains.txt

# Start from scratch in daemon mode
./dns-good -reset -mode run -input domains.txt
```

`-reset` removes:
- The SQLite database file (and its `-wal` / `-shm` sidecars)
- The entire output directory and all text files inside it

The database is recreated automatically when the run starts. `-reset` works
with any `-mode`, including `stats` (though that is rarely useful).

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


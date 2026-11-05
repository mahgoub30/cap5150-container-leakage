# CAP5150 Topic 23: container leakage testbed

Code and results for the CAP 5150 (Fall 2026, UCF) final project
"Measuring Information Exposure Between Tenants and the Performance Cost of
Mitigation". Two containers on one Docker host, used to measure what one
tenant can learn about another with no network path between them.

| Container | Role |
|---|---|
| `leak-victim` | runs a workload that we control (idle, CPU-heavy, disk-heavy) |
| `leak-attacker` | only observes; reads host-wide files under `/proc` and `/sys` |

Both are started with `--network none`, so there is no network path between
them. They are kept, not deleted, after a run. Quitting Docker Desktop only
stops them; `python lab.py up --tier N` starts a fresh pair.

## Tiers

| Tier | Settings |
|---|---|
| 1 | Docker default, `--network none` |
| 2 | Tier 1 + `--user 1000:1000`, `--read-only` (tmpfs `/tmp`), `--cap-drop ALL`, `no-new-privileges` |
| 3 | Tier 2 + `--cpuset-cpus` 0-1 (victim) / 2-3 (attacker), `--memory 2g` each |

`misconfig` adds two badly configured attackers next to the Tier 1 victim
(a privileged container and one with the Docker socket mounted). It only
reads what they can see.

## Host

Docker Desktop (engine 29.5.3) runs its engine inside the WSL 2 virtual
machine. A `.wslconfig` file in the Windows user folder with `[wsl2]` /
`processors=4` limits that VM to 4 vCPUs to match the proposal. Delete it and
run `wsl --shutdown` to give WSL all cores back.

## Running it

```
python lab.py build            # build the leaklab:1 image from image/
python lab.py all --tier 1     # every measurement, about 30 minutes
python lab.py all --tier 2
python lab.py all --tier 3
python lab.py up --tier 1      # victim must be running for misconfig
python lab.py misconfig
```

Single steps: `up`, `env`, `check`, `probe`, `guess`, `channel`, `fast`,
`perf`, `audit`, `summary`. `fast` repeats the channel test at 100, 200 and
500 bit/s. Keep the machine idle while `guess`, `channel` and `perf` run.

## What each step measures

| Step | Metric | How |
|---|---|---|
| `audit` | M1. CIS checks | Docker Bench for Security v1.6.0, cloned into `third_party/` on first run |
| `probe` | M2. host-wide files readable | `image/lab/probe.py` inside the attacker; 29 files from ContainerLeaks Table II plus 5 more |
| `guess` | M3. correct state guesses | victim switches state; `observe.py` in the attacker reads `/proc/stat` and `/proc/diskstats` and guesses |
| `channel`, `fast` | M4. message with no network | `sender.py` in the victim keeps the CPU busy for a 1; `receiver.py` in the attacker reads `/proc/stat` |
| `perf` | M5. performance | sysbench (CPU), fio (disk), iperf3 (network), 3 runs each |

## Results

`results/tier<N>/summary.txt` has the headline numbers for each tier. The
JSON files next to it hold every round, and `metric1_audit.txt` is the full
audit report. `results/misconfig/misconfig.json` holds the misconfigured
reference.

Tier 1 was first measured on 2026-10-11 (milestone). Tiers 2 and 3 were
measured on 2026-11-05. `results/tier1/metric5_perf_rerun.json` and
`metric4_channel_fast.json` are Tier 1 runs from the same day as Tiers 2 and
3; the overhead numbers in the report use that same-day baseline.

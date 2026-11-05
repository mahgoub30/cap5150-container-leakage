# cap5150-container-leakage

CAP 5150 final project (UCF, Fall 2026) - Topic 23: measuring information
exposure between tenants and the performance cost of mitigation.

Two containers run on the same Docker host with `--network none`:

- `leak-victim` runs a workload (idle, cpu, disk)
- `leak-attacker` only reads host-wide files under /proc and /sys

The same tests run at three tiers:

- Tier 1: Docker defaults
- Tier 2: non-root user, read-only root fs, `--cap-drop ALL`, no-new-privileges
- Tier 3: tier 2 + own CPUs (`--cpuset-cpus`) and a 2g memory limit

`misconfig` also runs a privileged container and one with docker.sock
mounted next to the victim, just to compare.

## Setup

Tested on Docker Desktop 29.5.3 (WSL 2), with WSL limited to 4 vCPUs in
`.wslconfig`:

```
[wsl2]
processors=4
```

## Usage

```
python lab.py build
python lab.py all --tier 1
python lab.py all --tier 2
python lab.py all --tier 3
python lab.py up --tier 1
python lab.py misconfig
```

`all` takes about 30 min per tier. Don't use the machine while it runs
(guess, channel and perf are sensitive to other load).

Steps can also be run one at a time: `up`, `env`, `check`, `probe`, `guess`,
`channel`, `fast`, `perf`, `audit`, `summary`.

| step | metric |
|---|---|
| audit | M1 - CIS checks (Docker Bench for Security, cloned into third_party/) |
| probe | M2 - host-wide files readable (29 from ContainerLeaks + 5 more) |
| guess | M3 - guessing the victim's state from /proc/stat and /proc/diskstats |
| channel, fast | M4 - sending bits with CPU load, no network |
| perf | M5 - sysbench, fio, iperf3 |

## Results

`results/tier1`, `tier2`, `tier3` and `misconfig` - each tier has a
`summary.txt` and the raw JSON.

Tier 1 was run on Oct 11 for the milestone. Tiers 2 and 3 were run on Nov 5,
along with a second tier 1 perf run (`metric5_perf_rerun.json`) used as the
baseline for overhead in the report.

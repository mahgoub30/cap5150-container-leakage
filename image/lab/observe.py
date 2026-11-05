# M3 (attacker). Measures how busy the host's CPUs and disks are over a few
# seconds and, if cut-offs are given, guesses the victim's state.
import argparse
import json
import re
import time

DISK = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+)$")


def cpu_ticks():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v), v[3] + v[4]  # total, idle + iowait


def disk_sectors():
    total = 0
    with open("/proc/diskstats") as f:
        for line in f:
            p = line.split()
            if DISK.match(p[2]):
                total += int(p[5]) + int(p[9])  # sectors read + written
    return total


ap = argparse.ArgumentParser()
ap.add_argument("--seconds", type=float, default=4)
ap.add_argument("--cpu-cut", type=float)
ap.add_argument("--disk-cut", type=float)
a = ap.parse_args()

t0, c0, d0 = time.time(), cpu_ticks(), disk_sectors()
time.sleep(a.seconds)
t1, c1, d1 = time.time(), cpu_ticks(), disk_sectors()

ticks = max(c1[0] - c0[0], 1)
with open("/proc/loadavg") as f:
    load1 = float(f.read().split()[0])
r = {"cpu_busy_pct": round(100 * (1 - (c1[1] - c0[1]) / ticks), 2),
     "disk_kb_s": round((d1 - d0) * 512 / 1024 / (t1 - t0), 1),
     "load1": load1}

if a.cpu_cut is not None:
    if r["disk_kb_s"] > a.disk_cut:
        r["guess"] = "disk"
    elif r["cpu_busy_pct"] > a.cpu_cut:
        r["guess"] = "cpu"
    else:
        r["guess"] = "idle"
print(json.dumps(r))

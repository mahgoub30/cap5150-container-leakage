"""Metric 3: guess what the neighbor is doing from host-wide counters.

Runs inside the attacker container. It reads /proc/stat, /proc/diskstats and
/proc/loadavg, waits, reads them again, and reports how busy the whole host's
CPUs and disks were in between. If cut-off values are given it also guesses
the victim's state: idle, cpu, or disk.
"""
import argparse
import json
import re
import time

WHOLE_DISK = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+)$")


def cpu_ticks():
    """Return (total ticks, idle ticks) summed over all CPUs of the host."""
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v), v[3] + v[4]  # idle + iowait count as not busy


def disk_sectors():
    """Sectors read plus written on every whole disk of the host."""
    total = 0
    with open("/proc/diskstats") as f:
        for line in f:
            p = line.split()
            if WHOLE_DISK.match(p[2]):
                total += int(p[5]) + int(p[9])
    return total


def load1():
    with open("/proc/loadavg") as f:
        return float(f.read().split()[0])


def observe(seconds):
    t0, c0, d0 = time.time(), cpu_ticks(), disk_sectors()
    time.sleep(seconds)
    t1, c1, d1 = time.time(), cpu_ticks(), disk_sectors()
    ticks = max(c1[0] - c0[0], 1)
    busy = 100.0 * (1 - (c1[1] - c0[1]) / ticks)
    disk_kb_s = (d1 - d0) * 512 / 1024 / (t1 - t0)
    return {"cpu_busy_pct": round(busy, 2), "disk_kb_s": round(disk_kb_s, 1),
            "load1": load1()}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=4)
    ap.add_argument("--cpu-cut", type=float)
    ap.add_argument("--disk-cut", type=float)
    a = ap.parse_args()
    r = observe(a.seconds)
    if a.cpu_cut is not None and a.disk_cut is not None:
        if r["disk_kb_s"] > a.disk_cut:
            r["guess"] = "disk"
        elif r["cpu_busy_pct"] > a.cpu_cut:
            r["guess"] = "cpu"
        else:
            r["guess"] = "idle"
    print(json.dumps(r))

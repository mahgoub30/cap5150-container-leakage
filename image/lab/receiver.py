"""Metric 4, receiving side. Runs inside the attacker container.

It reads the host-wide CPU counters in /proc/stat at every slot boundary and
works out how busy the host was in each slot. The first slots carry a known
pattern (the preamble), which is used to pick the cut-off between a 0 and a 1.
The remaining slots are decoded with that cut-off.
"""
import argparse
import json
import time


def cpu_ticks():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v), v[3] + v[4]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--slot", type=float, required=True)
    ap.add_argument("--n", type=int, required=True, help="slots incl. preamble")
    ap.add_argument("--preamble", required=True)
    a = ap.parse_args()

    samples = []
    for i in range(a.n + 1):
        wait = a.t0 + i * a.slot - time.time()
        if wait > 0:
            time.sleep(wait)
        samples.append(cpu_ticks())

    busy = []
    for (t0, i0), (t1, i1) in zip(samples, samples[1:]):
        ticks = t1 - t0
        busy.append(100.0 * (1 - (i1 - i0) / ticks) if ticks > 0 else 0.0)

    pre = a.preamble
    ones = [busy[i] for i, b in enumerate(pre) if b == "1"]
    zeros = [busy[i] for i, b in enumerate(pre) if b == "0"]
    cut = (sum(ones) / len(ones) + sum(zeros) / len(zeros)) / 2
    decoded = "".join("1" if x > cut else "0" for x in busy[len(pre):])
    print(json.dumps({"cut": round(cut, 2), "decoded": decoded,
                      "busy": [round(x, 1) for x in busy]}))

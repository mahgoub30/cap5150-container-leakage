# M4 receiver (attacker). Reads /proc/stat at every slot and decodes the bits.
# usage: receiver.py <start time> <slot seconds> <number of slots> <preamble>
import json
import sys
import time

t0, slot, n, pre = float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3]), sys.argv[4]


def cpu_ticks():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:9]]
    return sum(v), v[3] + v[4]  # total, idle + iowait


samples = []
for i in range(n + 1):
    time.sleep(max(0, t0 + i * slot - time.time()))
    samples.append(cpu_ticks())

busy = []
for (t_a, i_a), (t_b, i_b) in zip(samples, samples[1:]):
    ticks = t_b - t_a
    busy.append(100 * (1 - (i_b - i_a) / ticks) if ticks > 0 else 0.0)

# cut-off = halfway between the 1s and the 0s of the known preamble
ones = [busy[i] for i, b in enumerate(pre) if b == "1"]
zeros = [busy[i] for i, b in enumerate(pre) if b == "0"]
cut = (sum(ones) / len(ones) + sum(zeros) / len(zeros)) / 2
decoded = "".join("1" if x > cut else "0" for x in busy[len(pre):])
print(json.dumps({"cut": round(cut, 2), "decoded": decoded,
                  "busy": [round(x, 1) for x in busy]}))

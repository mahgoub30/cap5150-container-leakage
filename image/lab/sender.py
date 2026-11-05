"""Metric 4, sending side. Runs inside the victim container.

The message is a string of 0s and 1s. Time is cut into slots of equal length
starting at --t0 (the two containers share the host clock). For a 1 the sender
keeps the CPU busy for the whole slot. For a 0 it sleeps.
"""
import argparse
import multiprocessing
import time


def send(t0, slot, bits):
    for i, bit in enumerate(bits):
        start = t0 + i * slot
        end = start + slot
        wait = start - time.time()
        if wait > 0:
            time.sleep(wait)
        if bit == "1":
            while time.time() < end:
                pass
        else:
            wait = end - time.time()
            if wait > 0:
                time.sleep(wait)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--slot", type=float, required=True)
    ap.add_argument("--bits", required=True)
    ap.add_argument("--threads", type=int, default=2)
    a = ap.parse_args()
    workers = [multiprocessing.Process(target=send, args=(a.t0, a.slot, a.bits))
               for _ in range(a.threads - 1)]
    for w in workers:
        w.start()
    send(a.t0, a.slot, a.bits)
    for w in workers:
        w.join()

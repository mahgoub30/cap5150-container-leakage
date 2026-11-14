# M4 sender
# usage: sender.py <start time> <slot seconds> <bits>
import multiprocessing
import sys
import time

t0, slot, bits = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3]


def send():
    for i, bit in enumerate(bits):
        start = t0 + i * slot
        end = start + slot
        time.sleep(max(0, start - time.time()))
        if bit == "1":
            while time.time() < end:
                pass
        else:
            time.sleep(max(0, end - time.time()))


other = multiprocessing.Process(target=send)
other.start()
send()
other.join()

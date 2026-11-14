# M2, runs in the attacker
import glob
import json


def mount_points():
    with open("/proc/self/mountinfo") as f:
        return {line.split()[4] for line in f}

CANDIDATES = [
    # ContainerLeaks table II
    "/proc/sys/kernel/random/boot_id",
    "/sys/fs/cgroup/net_prio/net_prio.ifpriomap",
    "/proc/sched_debug",
    "/proc/timer_list",
    "/proc/locks",
    "/proc/uptime",
    "/proc/stat",
    "/proc/schedstat",
    "/proc/softirqs",
    "/proc/interrupts",
    "/sys/devices/system/node/node*/numastat",
    "/sys/class/powercap/*/energy_uj",
    "/sys/devices/system/cpu/cpu*/cpuidle/state*/usage",
    "/sys/devices/system/cpu/cpu*/cpuidle/state*/time",
    "/proc/sys/fs/dentry-state",
    "/proc/sys/fs/inode-nr",
    "/proc/sys/fs/file-nr",
    "/proc/zoneinfo",
    "/proc/meminfo",
    "/proc/fs/ext4/*/mb_groups",
    "/sys/devices/system/node/node*/vmstat",
    "/sys/devices/system/node/node*/meminfo",
    "/sys/devices/platform/coretemp.*/hwmon/hwmon*/temp*_input",
    "/proc/loadavg",
    "/proc/sys/kernel/random/entropy_avail",
    "/proc/sys/kernel/sched_domain/cpu*/domain*/max_newidle_lb_cost",
    "/proc/modules",
    "/proc/cpuinfo",
    "/proc/version",
    # extra
    "/proc/diskstats",
    "/proc/vmstat",
    "/proc/buddyinfo",
    "/proc/swaps",
    "/sys/devices/system/cpu/online",
]


def check(pattern):
    matches = sorted(glob.glob(pattern))
    if not matches:
        return {"file": pattern, "status": "absent", "sample": ""}
    path = matches[0]
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read(4096)
    except OSError as e:
        return {"file": path, "status": "denied", "sample": type(e).__name__}
    if not data.strip():
        status = "masked" if path in MOUNTS else "empty"
        return {"file": path, "status": status, "sample": ""}
    first = data.strip().splitlines()[0]
    return {"file": path, "status": "readable", "sample": first[:70]}


MOUNTS = mount_points()

if __name__ == "__main__":
    print(json.dumps([check(p) for p in CANDIDATES]))

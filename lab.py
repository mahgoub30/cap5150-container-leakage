# CAP5150 Topic 23 testbed: victim + attacker container on one Docker host,
# no network between them.
#
#   python lab.py build
#   python lab.py all --tier 1          (tier 1, 2 or 3)
#   python lab.py <step> --tier 1       up env check probe guess channel fast
#                                       perf audit summary
#   python lab.py misconfig             (with the tier 1 containers running)
#
# results are saved in results/tier<N>/

import datetime
import json
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
IMAGE = "leaklab:1"
VICTIM = "leak-victim"
ATTACKER = "leak-attacker"
STATES = ["idle", "cpu", "disk"]
STATUSES = ["readable", "masked", "empty", "denied", "absent"]

HARDENED = ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
TIERS = {
    1: {"name": "Docker default", "both": [], "victim": [], "attacker": []},
    2: {"name": "hardened", "both": HARDENED, "victim": [], "attacker": []},
    3: {"name": "hardened + own CPU and memory", "both": HARDENED,
        "victim": ["--cpuset-cpus", "0-1", "--memory", "2g"],
        "attacker": ["--cpuset-cpus", "2-3", "--memory", "2g"]},
}


def docker(*args):
    r = subprocess.run(["docker", *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return r.stdout.strip()


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def save(tier, name, data):
    folder = HERE / "results" / f"tier{tier}"
    folder.mkdir(parents=True, exist_ok=True)
    data = {"collected": now(), "tier": tier, **data}
    (folder / name).write_text(json.dumps(data, indent=2))
    print(name, "saved")


def volume(tier):
    # tier 1 writes as root, so tiers 2 and 3 need their own volume
    return "leak-victim-data" if tier == 1 else f"leak-victim-data-t{tier}"


# ---- setup

def up(tier):
    t = TIERS[tier]
    docker("volume", "create", volume(tier))
    docker("rm", "-f", VICTIM, ATTACKER)
    common = ["--network", "none", "--label", f"tier={tier}", *t["both"]]
    docker("run", "-d", "--name", VICTIM, "--hostname", "victim",
           "-v", f"{volume(tier)}:/data", *common, *t["victim"], IMAGE)
    docker("run", "-d", "--name", ATTACKER, "--hostname", "attacker",
           *common, *t["attacker"], IMAGE)
    # file used by the victim's disk workload
    docker("exec", VICTIM, "fio", "--name=prep", "--filename=/data/victim.bin",
           "--size=64M", "--rw=write", "--bs=1M", "--direct=1",
           "--output=/dev/null")


def env(tier):
    info = json.loads(docker("info", "--format", "{{json .}}"))
    save(tier, "environment.json", {
        "docker_server": info["ServerVersion"],
        "os": info["OperatingSystem"],
        "kernel": info["KernelVersion"],
        "cpus": info["NCPU"],
        "memory_gb": round(info["MemTotal"] / 2**30, 1),
        "storage_driver": info["Driver"],
        "cgroup_version": info["CgroupVersion"],
        "security_options": info["SecurityOptions"],
        "default_runtime": info["DefaultRuntime"],
        "image": docker("image", "inspect", IMAGE, "--format", "{{.Id}}"),
        "tier_flags": TIERS[tier]})


def check(tier):
    # container settings, no network, and same host (same boot_id)
    res = {}
    for c in (VICTIM, ATTACKER):
        i = json.loads(docker("inspect", c))[0]
        h = i["HostConfig"]
        addrs = docker("exec", c, "ip", "-o", "addr").splitlines()
        res[c] = {
            "state": i["State"]["Status"],
            "network_mode": h["NetworkMode"],
            "user": i["Config"]["User"] or "root (default)",
            "read_only": h["ReadonlyRootfs"],
            "privileged": h["Privileged"],
            "cap_drop": h["CapDrop"],
            "security_opt": h["SecurityOpt"],
            "cpuset": h["CpusetCpus"],
            "memory_limit": h["Memory"],
            "addresses": [a.split()[3] for a in addrs],
            "boot_id": docker("exec", c, "cat", "/proc/sys/kernel/random/boot_id"),
            "cpus_seen": int(docker("exec", c, "grep", "-c", "^processor", "/proc/cpuinfo")),
            "memtotal_seen": " ".join(docker("exec", c, "grep", "MemTotal",
                                             "/proc/meminfo").split())}
    res["same_boot_id"] = res[VICTIM]["boot_id"] == res[ATTACKER]["boot_id"]
    res["no_network_path"] = all(
        res[c]["network_mode"] == "none" and
        all(a.startswith(("127.", "::1")) for a in res[c]["addresses"])
        for c in (VICTIM, ATTACKER))
    save(tier, "check.json", res)


# ---- M1: CIS audit (Docker Bench for Security)

def audit(tier):
    bench = HERE / "third_party" / "docker-bench-security"
    if not bench.exists():
        # autocrlf=false so the shell scripts keep unix line endings
        subprocess.run(["git", "clone", "-c", "core.autocrlf=false", "--depth", "1",
                        "https://github.com/docker/docker-bench-security.git",
                        str(bench)])
    commit = subprocess.run(["git", "-C", str(bench), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    docker("build", "-t", "docker-bench-security:current", str(bench))
    text = docker("run", "--rm", "--net", "host", "--pid", "host", "--userns", "host",
                  "--cap-add", "audit_control", "-e", "DOCKER_CONTENT_TRUST=0",
                  "-v", "/etc:/etc:ro", "-v", "/var/lib:/var/lib:ro",
                  "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                  "--label", "docker_bench_security", "docker-bench-security:current")
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)  # remove colors
    (HERE / "results" / f"tier{tier}" / "metric1_audit.txt").write_text(text)

    counts = {"PASS": 0, "WARN": 0, "INFO": 0, "NOTE": 0}
    warnings = []
    for line in text.splitlines():
        m = re.match(r"\[(PASS|WARN|INFO|NOTE)\]\s+(\d+\.\d+(?:\.\d+)?)\s+-?\s*(.*)", line)
        if m:
            counts[m.group(1)] += 1
            if m.group(1) == "WARN":
                warnings.append(m.group(2) + " " + m.group(3))
    save(tier, "metric1_audit.json", {
        "script_version": re.search(r"Docker Bench for Security v([\d.]+)", text).group(1),
        "script_commit": commit,
        "checks_reported": int(re.search(r"Checks:\s*(-?\d+)", text).group(1)),
        "score_reported": int(re.search(r"Score:\s*(-?\d+)", text).group(1)),
        "numbered_checks": counts,
        "warnings": warnings})


# ---- M2: host-wide files the attacker can read

def probe(tier):
    rows = json.loads(docker("exec", ATTACKER, "python3", "/lab/probe.py"))
    count = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
    save(tier, "metric2_probe.json", {"candidates": len(rows), "count": count,
                                      "present": len(rows) - count["absent"],
                                      "files": rows})


# ---- M3: guess the victim's state (idle / cpu / disk)

def start_victim(state):
    if state == "cpu":
        docker("exec", "-d", VICTIM, "sysbench", "cpu", "--threads=2",
               "--time=6", "run")
    if state == "disk":
        docker("exec", "-d", VICTIM, "fio", "--name=victim",
               "--filename=/data/victim.bin", "--size=64M", "--rw=randrw",
               "--bs=64k", "--direct=1", "--runtime=6", "--time_based",
               "--output=/dev/null")


def one_round(state, cuts=None):
    start_victim(state)
    time.sleep(0.8)
    cmd = ["exec", ATTACKER, "python3", "/lab/observe.py", "--seconds", "4"]
    if cuts:
        cmd += ["--cpu-cut", str(cuts["cpu"]), "--disk-cut", str(cuts["disk"])]
    result = json.loads(docker(*cmd))
    time.sleep(3)  # let the host go quiet again
    return {"actual": state, **result}


def guess(tier):
    rng = random.Random(23)

    # 15 practice rounds (5 per state) to set the two cut-offs
    order = STATES * 5
    rng.shuffle(order)
    calib = [one_round(s) for s in order]

    def avg(key, states):
        return statistics.mean(r[key] for r in calib if r["actual"] in states)

    cuts = {"cpu": round((avg("cpu_busy_pct", ["idle"]) + avg("cpu_busy_pct", ["cpu"])) / 2, 2),
            "disk": round((avg("disk_kb_s", ["idle", "cpu"]) + avg("disk_kb_s", ["disk"])) / 2, 1)}

    # 60 test rounds (20 per state)
    order = STATES * 20
    rng.shuffle(order)
    rounds = [one_round(s, cuts) for s in order]

    table = {s: {g: sum(r["actual"] == s and r["guess"] == g for r in rounds)
                 for g in STATES} for s in STATES}
    correct = sum(r["actual"] == r["guess"] for r in rounds)
    print(f"{correct}/{len(rounds)} correct")
    save(tier, "metric3_guess.json", {
        "seconds_per_round": 4.0, "cutoffs": cuts, "correct": correct,
        "rounds_total": len(rounds),
        "correct_pct": round(100 * correct / len(rounds), 1),
        "actual_vs_guess": table, "calibration": calib, "rounds": rounds})


# ---- M4: send a message with CPU load, no network

def channel(tier, slots=(0.5, 0.2, 0.1, 0.05, 0.02), name="metric4_channel.json"):
    rng = random.Random(23)
    msg = "".join(rng.choice("01") for _ in range(128))
    pre = "10" * 8  # known start pattern, used by the receiver to set its cut-off
    runs = []
    for slot in slots:
        for rep in (1, 2, 3):
            t0 = float(docker("exec", ATTACKER, "python3", "-c",
                              "import time; print(time.time())")) + 3
            docker("exec", "-d", VICTIM, "python3", "/lab/sender.py",
                   str(t0), str(slot), pre + msg)
            got = json.loads(docker("exec", ATTACKER, "python3", "/lab/receiver.py",
                                    str(t0), str(slot), str(len(pre + msg)), pre))
            wrong = sum(a != b for a, b in zip(msg, got["decoded"]))
            print(f"{1 / slot:.0f} bit/s, run {rep}: {wrong}/128 wrong")
            runs.append({"slot_s": slot, "repeat": rep, "bits": 128,
                         "bits_per_s": round(1 / slot, 1), "wrong_bits": wrong,
                         "wrong_pct": round(100 * wrong / 128, 1),
                         "cut": got["cut"], "decoded": got["decoded"]})
            time.sleep(2)

    by_slot = []
    for slot in slots:
        wrong = sum(r["wrong_bits"] for r in runs if r["slot_s"] == slot)
        by_slot.append({"slot_s": slot, "bits_per_s": round(1 / slot, 1),
                        "bits_sent": 384, "wrong_bits": wrong,
                        "wrong_pct": round(100 * wrong / 384, 1)})
    save(tier, name, {"message_bits": 128, "message": msg, "preamble": pre,
                      "sender_threads": 2, "by_slot": by_slot, "runs": runs})


def fast(tier):
    # 100, 200 and 500 bit/s
    channel(tier, (0.01, 0.005, 0.002), "metric4_channel_fast.json")


# ---- M5: performance (sysbench, fio, iperf3), 3 runs each

def perf(tier, name="metric5_perf.json"):
    both = TIERS[tier]["both"]
    cpu, disk, net = [], [], []
    for _ in range(3):
        out = docker("exec", VICTIM, "sysbench", "cpu", "--threads=4",
                     "--cpu-max-prime=20000", "--time=10", "run")
        cpu.append({"events_per_s": float(re.search(r"events per second:\s*([\d.]+)", out).group(1)),
                    "avg_latency_ms": float(re.search(r"avg:\s*([\d.]+)", out).group(1))})
    for _ in range(3):
        out = docker("exec", VICTIM, "fio", "--name=perf", "--filename=/data/perf.bin",
                     "--size=256M", "--rw=randrw", "--rwmixread=50", "--bs=4k",
                     "--direct=1", "--ioengine=libaio", "--iodepth=16", "--runtime=15",
                     "--time_based", "--group_reporting", "--output-format=json")
        job = json.loads(out[out.index("{"):])["jobs"][0]
        disk.append({"iops": round(job["read"]["iops"] + job["write"]["iops"]),
                     "mb_per_s": round((job["read"]["bw"] + job["write"]["bw"]) / 1024, 1)})

    # network: iperf3 server and client containers on the default bridge
    docker("rm", "-f", "leak-iperf-server")
    docker("run", "-d", "--name", "leak-iperf-server", *both, IMAGE, "iperf3", "-s")
    ip = docker("inspect", "leak-iperf-server", "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
    time.sleep(1.5)
    for _ in range(3):
        out = docker("run", "--rm", *both, IMAGE, "iperf3", "-c", ip, "-t", "10", "-J")
        bps = json.loads(out)["end"]["sum_received"]["bits_per_second"]
        net.append({"gbit_per_s": round(bps / 1e9, 2)})
    docker("rm", "-f", "leak-iperf-server")

    def avg(rows, key):
        return round(statistics.mean(r[key] for r in rows), 2)

    save(tier, name, {
        "runs_each": 3,
        "cpu_events_per_s": avg(cpu, "events_per_s"),
        "cpu_avg_latency_ms": avg(cpu, "avg_latency_ms"),
        "disk_iops": avg(disk, "iops"), "disk_mb_per_s": avg(disk, "mb_per_s"),
        "network_gbit_per_s": avg(net, "gbit_per_s"),
        "cpu_runs": cpu, "disk_runs": disk, "network_runs": net})


def summary(tier):
    folder = HERE / "results" / f"tier{tier}"

    def load(name):
        return json.loads((folder / name).read_text())

    m1, m2, m3 = load("metric1_audit.json"), load("metric2_probe.json"), load("metric3_guess.json")
    m5 = load("metric5_perf.json")
    lines = [f"Tier {tier} ({TIERS[tier]['name']})",
             f"M1: {m1['numbered_checks']['PASS']} pass, {m1['numbered_checks']['WARN']} warn",
             f"M2: {m2['count']['readable']} of {m2['present']} files readable",
             f"M3: {m3['correct']}/{m3['rounds_total']} correct"]
    for name in ("metric4_channel.json", "metric4_channel_fast.json"):
        for r in load(name)["by_slot"]:
            lines.append(f"M4: {r['bits_per_s']} bit/s, {r['wrong_pct']}% wrong")
    lines.append(f"M5: cpu {m5['cpu_events_per_s']} events/s, disk {m5['disk_iops']} IOPS, "
                 f"network {m5['network_gbit_per_s']} Gbit/s")
    (folder / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


# ---- misconfigured containers, for comparison (read only)

LIST_CONTAINERS = r"""
import json, socket
s = socket.socket(socket.AF_UNIX)
s.connect('/var/run/docker.sock')
s.sendall(b'GET /containers/json HTTP/1.0\r\nHost: docker\r\n\r\n')
data = b''
while True:
    part = s.recv(65536)
    if not part:
        break
    data += part
rows = json.loads(data.split(b'\r\n\r\n', 1)[1])
print(json.dumps([r['Names'][0].lstrip('/') for r in rows]))
"""


def misconfig():
    base = ["run", "--rm", "--network", "none"]
    rows = json.loads(docker(*base, "--privileged", IMAGE, "python3", "/lab/probe.py"))
    disks = docker(*base, "--privileged", IMAGE, "sh", "-c",
                   "ls /dev | grep -E '^(sd|vd|nvme)' || true").split()
    seen = json.loads(docker(*base, "-v", "/var/run/docker.sock:/var/run/docker.sock",
                             IMAGE, "python3", "-c", LIST_CONTAINERS))
    res = {"collected": now(),
           "privileged_probe": {s: sum(r["status"] == s for r in rows) for s in STATUSES},
           "privileged_masked_files_now_readable": [
               r["file"] for r in rows if r["status"] == "readable" and
               r["file"] in ("/proc/timer_list", "/proc/interrupts")],
           "privileged_host_block_devices": disks,
           "socket_sees_containers": seen,
           "socket_sees_victim": VICTIM in seen}
    folder = HERE / "results" / "misconfig"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "misconfig.json").write_text(json.dumps(res, indent=2))


STEPS = {"up": up, "env": env, "check": check, "probe": probe, "guess": guess,
         "channel": channel, "fast": fast, "perf": perf, "audit": audit,
         "summary": summary}

if __name__ == "__main__":
    step = sys.argv[1]
    tier = int(sys.argv[sys.argv.index("--tier") + 1]) if "--tier" in sys.argv else 1
    if step == "build":
        docker("build", "-t", IMAGE, str(HERE / "image"))
    elif step == "misconfig":
        misconfig()
    elif step == "all":
        for name in STEPS:
            print("==", name)
            STEPS[name](tier)
    else:
        STEPS[step](tier)

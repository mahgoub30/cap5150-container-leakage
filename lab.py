"""CAP5150 Topic 23 testbed: two containers on one Docker host.

leak-victim   runs a workload that we control
leak-attacker only observes; it has no network connection to the victim

Run from this folder:
    python lab.py build            build the container image
    python lab.py up --tier 1      create and start the two containers
    python lab.py all --tier 1     run every measurement and save the results
    python lab.py misconfig        privileged / docker.sock comparison
Single steps: env, check, probe, guess, channel, fast, perf, audit, summary.
Results go to results/tier<N>/ as JSON plus a summary.txt.
"""
import argparse
import datetime
import json
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = "leaklab:1"
VICTIM, ATTACKER = "leak-victim", "leak-attacker"
VOLUME = "leak-victim-data"
BENCH_REPO = "https://github.com/docker/docker-bench-security.git"
BENCH_DIR = HERE / "third_party" / "docker-bench-security"
BENCH_IMAGE = "docker-bench-security:current"


def volume(tier):
    # new volume per tier: tier 1 writes its files as root and the
    # non-root user in tiers 2/3 can't overwrite them
    return VOLUME if tier == 1 else f"{VOLUME}-t{tier}"


# tier settings (from the proposal)
HARDENED = ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
TIERS = {
    1: {"name": "Docker default", "both": [], "victim": [], "attacker": []},
    2: {"name": "hardened", "both": HARDENED, "victim": [], "attacker": []},
    3: {"name": "hardened + own CPU and memory", "both": HARDENED,
        "victim": ["--cpuset-cpus", "0-1", "--memory", "2g"],
        "attacker": ["--cpuset-cpus", "2-3", "--memory", "2g"]},
}
STATES = ["idle", "cpu", "disk"]


def docker(*args, check=True):
    r = subprocess.run(["docker", *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        sys.exit(f"docker {' '.join(args)}\nfailed: {r.stderr.strip()}")
    return r.stdout.strip()


def outdir(tier):
    d = HERE / "results" / f"tier{tier}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(tier, name, data):
    data = {"collected": datetime.datetime.now().isoformat(timespec="seconds"),
            "tier": tier, **data}
    (outdir(tier) / name).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def say(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- setup

def cmd_build(a):
    say(docker("build", "-t", IMAGE, str(HERE / "image")) or "image built")


def cmd_up(a):
    t = TIERS[a.tier]
    docker("volume", "create", volume(a.tier))
    docker("rm", "-f", VICTIM, ATTACKER, check=False)
    common = ["--network", "none", "--label", "project=cap5150-topic23",
              "--label", f"tier={a.tier}", *t["both"]]
    docker("run", "-d", "--name", VICTIM, "--hostname", "victim",
           "-v", f"{volume(a.tier)}:/data", *common, *t["victim"], IMAGE)
    docker("run", "-d", "--name", ATTACKER, "--hostname", "attacker",
           *common, *t["attacker"], IMAGE)
    # lay out the file the victim's disk workload uses
    docker("exec", VICTIM, "fio", "--name=prep", "--filename=/data/victim.bin",
           "--size=64M", "--rw=write", "--bs=1M", "--direct=1",
           "--output=/dev/null")
    say(f"tier {a.tier} ({t['name']}): {VICTIM} and {ATTACKER} are running")


def cmd_env(a):
    info = json.loads(docker("info", "--format", "{{json .}}"))
    env = {
        "docker_server": info.get("ServerVersion"),
        "os": info.get("OperatingSystem"),
        "kernel": info.get("KernelVersion"),
        "cpus": info.get("NCPU"),
        "memory_gb": round(info.get("MemTotal", 0) / 2**30, 1),
        "storage_driver": info.get("Driver"),
        "cgroup_version": info.get("CgroupVersion"),
        "security_options": info.get("SecurityOptions"),
        "default_runtime": info.get("DefaultRuntime"),
        "image": docker("image", "inspect", IMAGE, "--format", "{{.Id}}"),
        "tier_flags": TIERS[a.tier],
    }
    save(a.tier, "environment.json", env)
    say(json.dumps(env, indent=2))


def cmd_check(a):
    """Show how the two containers are configured and that no network joins them."""
    res = {}
    for c in (VICTIM, ATTACKER):
        i = json.loads(docker("inspect", c))[0]
        h = i["HostConfig"]
        res[c] = {"state": i["State"]["Status"], "network_mode": h["NetworkMode"],
                  "user": i["Config"]["User"] or "root (default)",
                  "read_only": h["ReadonlyRootfs"], "privileged": h["Privileged"],
                  "cap_drop": h["CapDrop"], "security_opt": h["SecurityOpt"],
                  "cpuset": h["CpusetCpus"], "memory_limit": h["Memory"]}
        # every address the container has; with no network only loopback is left
        res[c]["addresses"] = [l.split()[3] for l in
                               docker("exec", c, "ip", "-o", "addr").splitlines()]
        res[c]["boot_id"] = docker("exec", c, "cat", "/proc/sys/kernel/random/boot_id")
        res[c]["cpus_seen"] = int(docker("exec", c, "grep", "-c", "^processor",
                                         "/proc/cpuinfo"))
        res[c]["memtotal_seen"] = " ".join(
            docker("exec", c, "grep", "MemTotal", "/proc/meminfo").split())
    res["same_boot_id"] = res[VICTIM]["boot_id"] == res[ATTACKER]["boot_id"]
    res["no_network_path"] = all(
        res[c]["network_mode"] == "none"
        and all(x.startswith(("127.", "::1")) for x in res[c]["addresses"])
        for c in (VICTIM, ATTACKER))
    save(a.tier, "check.json", res)
    say(json.dumps(res, indent=2))


# ---------------------------------------------------------------- metric 1

def cmd_audit(a):
    if not BENCH_DIR.exists():
        BENCH_DIR.parent.mkdir(parents=True, exist_ok=True)
        # keep Unix line endings, or the shell scripts break inside the image
        subprocess.run(["git", "clone", "-c", "core.autocrlf=false", "--depth", "1",
                        BENCH_REPO, str(BENCH_DIR)], check=True)
    commit = subprocess.run(["git", "-C", str(BENCH_DIR), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    docker("build", "-t", BENCH_IMAGE, str(BENCH_DIR))
    raw = docker("run", "--rm", "--net", "host", "--pid", "host", "--userns", "host",
                 "--cap-add", "audit_control", "-e", "DOCKER_CONTENT_TRUST=0",
                 "-v", "/etc:/etc:ro", "-v", "/var/lib:/var/lib:ro",
                 "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                 "--label", "docker_bench_security", BENCH_IMAGE, check=False)
    if "Docker Bench for Security" not in raw:
        sys.exit("the audit produced no report; run the docker command by hand to see why")
    text = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    (outdir(a.tier) / "metric1_audit.txt").write_text(text, encoding="utf-8")
    counts, warns = {"PASS": 0, "WARN": 0, "INFO": 0, "NOTE": 0}, []
    for line in text.splitlines():
        m = re.match(r"\[(PASS|WARN|INFO|NOTE)\]\s+(\d+\.\d+(?:\.\d+)?)\s+-?\s*(.*)", line)
        if m:  # one line per numbered check; detail lines have no number
            counts[m.group(1)] += 1
            if m.group(1) == "WARN":
                warns.append(f"{m.group(2)} {m.group(3)}")
    grab = lambda k: next((int(x) for x in re.findall(rf"{k}:\s*(-?\d+)", text)), None)
    version = next(iter(re.findall(r"Docker Bench for Security v([\d.]+)", text)), None)
    res = save(a.tier, "metric1_audit.json", {
        "script_version": version, "script_commit": commit,
        "checks_reported": grab("Checks"), "score_reported": grab("Score"),
        "numbered_checks": counts, "warnings": warns})
    say(json.dumps({k: res[k] for k in ("script_version", "checks_reported",
                                        "score_reported", "numbered_checks")}, indent=2))


# ---------------------------------------------------------------- metric 2

def cmd_probe(a):
    rows = json.loads(docker("exec", ATTACKER, "python3", "/lab/probe.py"))
    count = {s: sum(r["status"] == s for r in rows)
             for s in ("readable", "masked", "empty", "denied", "absent")}
    res = save(a.tier, "metric2_probe.json",
               {"candidates": len(rows), "count": count,
                "present": len(rows) - count["absent"], "files": rows})
    for r in rows:
        say(f"  {r['status']:9} {r['file']}")
    say(json.dumps({"candidates": res["candidates"], "present": res["present"],
                    **count}))


# ---------------------------------------------------------------- metric 3

def start_victim(state, seconds):
    if state == "cpu":
        docker("exec", "-d", VICTIM, "sysbench", "cpu", "--threads=2",
               f"--time={seconds}", "run")
    elif state == "disk":
        docker("exec", "-d", VICTIM, "fio", "--name=victim",
               "--filename=/data/victim.bin", "--size=64M", "--rw=randrw",
               "--bs=64k", "--direct=1", f"--runtime={seconds}", "--time_based",
               "--output=/dev/null")


def one_round(state, seconds, cuts=None):
    start_victim(state, int(round(seconds)) + 2)
    time.sleep(0.8)  # let the workload get going
    cmd = ["exec", ATTACKER, "python3", "/lab/observe.py", "--seconds", str(seconds)]
    if cuts:
        cmd += ["--cpu-cut", str(cuts["cpu"]), "--disk-cut", str(cuts["disk"])]
    obs = json.loads(docker(*cmd))
    time.sleep(3.0)  # let the workload end and the host settle
    return {"actual": state, **obs}


def cmd_guess(a):
    rng = random.Random(23)
    order = STATES * a.calib
    rng.shuffle(order)
    say(f"calibration: {len(order)} labeled rounds of {a.seconds}s")
    calib = [one_round(s, a.seconds) for s in order]
    mean = lambda key, states: statistics.mean(
        r[key] for r in calib if r["actual"] in states)
    cuts = {"cpu": round((mean("cpu_busy_pct", ["idle"]) +
                          mean("cpu_busy_pct", ["cpu"])) / 2, 2),
            "disk": round((mean("disk_kb_s", ["idle", "cpu"]) +
                           mean("disk_kb_s", ["disk"])) / 2, 1)}
    say(f"cut-offs: {cuts}")

    order = STATES * a.trials
    rng.shuffle(order)
    say(f"test: {len(order)} rounds")
    rounds = []
    for i, s in enumerate(order, 1):
        r = one_round(s, a.seconds, cuts)
        rounds.append(r)
        say(f"  {i:3}/{len(order)} actual={s:4} guess={r['guess']:4} "
            f"cpu={r['cpu_busy_pct']:5.1f}% disk={r['disk_kb_s']:9.1f} kB/s")
    table = {s: {g: sum(r["actual"] == s and r["guess"] == g for r in rounds)
                 for g in STATES} for s in STATES}
    correct = sum(r["actual"] == r["guess"] for r in rounds)
    res = save(a.tier, "metric3_guess.json", {
        "seconds_per_round": a.seconds, "cutoffs": cuts,
        "correct": correct, "rounds_total": len(rounds),
        "correct_pct": round(100 * correct / len(rounds), 1),
        "actual_vs_guess": table, "calibration": calib, "rounds": rounds})
    say(json.dumps({k: res[k] for k in ("correct", "rounds_total", "correct_pct",
                                        "actual_vs_guess")}, indent=2))


# ---------------------------------------------------------------- metric 4

def cmd_channel(a):
    rng = random.Random(23)
    msg = "".join(rng.choice("01") for _ in range(a.nbits))
    pre = "10" * 8
    runs = []
    for slot in a.slots:
        for rep in range(1, a.repeats + 1):
            now = float(docker("exec", ATTACKER, "python3", "-c",
                               "import time; print(time.time())"))
            t0 = now + 3
            docker("exec", "-d", VICTIM, "python3", "/lab/sender.py",
                   "--t0", str(t0), "--slot", str(slot), "--bits", pre + msg,
                   "--threads", "2")
            got = json.loads(docker("exec", ATTACKER, "python3", "/lab/receiver.py",
                                    "--t0", str(t0), "--slot", str(slot),
                                    "--n", str(len(pre + msg)), "--preamble", pre))
            wrong = sum(x != y for x, y in zip(msg, got["decoded"]))
            runs.append({"slot_s": slot, "repeat": rep, "bits": a.nbits,
                         "bits_per_s": round(1 / slot, 1), "wrong_bits": wrong,
                         "wrong_pct": round(100 * wrong / a.nbits, 1),
                         "cut": got["cut"], "decoded": got["decoded"]})
            say(f"  slot {slot:5}s  run {rep}: {round(1 / slot, 1):5} bit/s, "
                f"{wrong:3}/{a.nbits} bits wrong")
            time.sleep(2)
    by_slot = []
    for slot in a.slots:
        rs = [r for r in runs if r["slot_s"] == slot]
        wrong = sum(r["wrong_bits"] for r in rs)
        by_slot.append({"slot_s": slot, "bits_per_s": round(1 / slot, 1),
                        "bits_sent": a.nbits * len(rs), "wrong_bits": wrong,
                        "wrong_pct": round(100 * wrong / (a.nbits * len(rs)), 1)})
    res = save(a.tier, f"metric4_channel{a.tag}.json", {
        "message_bits": a.nbits, "message": msg, "preamble": pre,
        "sender_threads": 2, "by_slot": by_slot, "runs": runs})
    say(json.dumps(res["by_slot"], indent=2))


# ---------------------------------------------------------------- metric 5

def cmd_perf(a):
    t = TIERS[a.tier]
    cpu, disk, net = [], [], []
    for i in range(a.runs):
        out = docker("exec", VICTIM, "sysbench", "cpu", "--threads=4",
                     "--cpu-max-prime=20000", "--time=10", "run")
        cpu.append({"events_per_s": float(re.search(r"events per second:\s*([\d.]+)", out).group(1)),
                    "avg_latency_ms": float(re.search(r"avg:\s*([\d.]+)", out).group(1))})
        say(f"  cpu run {i + 1}: {cpu[-1]}")
    for i in range(a.runs):
        out = docker("exec", VICTIM, "fio", "--name=perf", "--filename=/data/perf.bin",
                     "--size=256M", "--rw=randrw", "--rwmixread=50", "--bs=4k",
                     "--direct=1", "--ioengine=libaio", "--iodepth=16", "--runtime=15",
                     "--time_based", "--group_reporting", "--output-format=json")
        job = json.loads(out[out.index("{"):])["jobs"][0]
        disk.append({"iops": round(job["read"]["iops"] + job["write"]["iops"]),
                     "mb_per_s": round((job["read"]["bw"] + job["write"]["bw"]) / 1024, 1)})
        say(f"  disk run {i + 1}: {disk[-1]}")
    # network: a server and a client container on Docker's default bridge
    docker("rm", "-f", "leak-iperf-server", check=False)
    docker("run", "-d", "--name", "leak-iperf-server", *t["both"], IMAGE, "iperf3", "-s")
    ip = docker("inspect", "leak-iperf-server", "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
    time.sleep(1.5)
    for i in range(a.runs):
        out = docker("run", "--rm", *t["both"], IMAGE, "iperf3", "-c", ip, "-t", "10", "-J")
        bps = json.loads(out)["end"]["sum_received"]["bits_per_second"]
        net.append({"gbit_per_s": round(bps / 1e9, 2)})
        say(f"  network run {i + 1}: {net[-1]}")
    docker("rm", "-f", "leak-iperf-server", check=False)
    avg = lambda rows, k: round(statistics.mean(r[k] for r in rows), 2)
    res = save(a.tier, f"metric5_perf{a.tag}.json", {
        "runs_each": a.runs,
        "cpu_events_per_s": avg(cpu, "events_per_s"),
        "cpu_avg_latency_ms": avg(cpu, "avg_latency_ms"),
        "disk_iops": avg(disk, "iops"), "disk_mb_per_s": avg(disk, "mb_per_s"),
        "network_gbit_per_s": avg(net, "gbit_per_s"),
        "cpu_runs": cpu, "disk_runs": disk, "network_runs": net})
    say(json.dumps({k: v for k, v in res.items() if not k.endswith("_runs")}, indent=2))


# ---------------------------------------------------------------- summary

def cmd_summary(a):
    d = outdir(a.tier)
    load = lambda n: json.loads((d / n).read_text(encoding="utf-8")) if (d / n).exists() else None
    env, chk = load("environment.json"), load("check.json")
    m1, m2, m3 = load("metric1_audit.json"), load("metric2_probe.json"), load("metric3_guess.json")
    m4, m5 = load("metric4_channel.json"), load("metric5_perf.json")
    L = [f"Tier {a.tier} ({TIERS[a.tier]['name']}) results"]
    if env:
        L.append(f"Host: {env['os']}, Docker {env['docker_server']}, kernel {env['kernel']}, "
                 f"{env['cpus']} vCPUs, {env['memory_gb']} GB (collected {env['collected']})")
    if chk:
        L.append(f"Containers: {VICTIM} and {ATTACKER}; no network path: {chk['no_network_path']}; "
                 f"same boot_id seen in both: {chk['same_boot_id']}")
    if m1:
        c = m1["numbered_checks"]
        L.append(f"Metric 1 (CIS audit, Docker Bench v{m1['script_version']}): "
                 f"{c['PASS']} pass, {c['WARN']} warn, {c['INFO']} info, {c['NOTE']} note; "
                 f"script reports Checks={m1['checks_reported']} Score={m1['score_reported']}")
    if m2:
        c = m2["count"]
        L.append(f"Metric 2 (host-wide files): {m2['candidates']} checked, {m2['present']} exist on "
                 f"this host, {c['readable']} readable, {c['masked']} masked by Docker, "
                 f"{c['empty']} empty, {c['denied']} denied")
    if m3:
        L.append(f"Metric 3 (state guessing): {m3['correct']}/{m3['rounds_total']} correct "
                 f"({m3['correct_pct']}%), cut-offs {m3['cutoffs']}")
        for s in STATES:
            L.append(f"    actual {s:4} -> guessed {m3['actual_vs_guess'][s]}")
    if m4:
        L.append(f"Metric 4 (message with no network, {m4['message_bits']} bits per run):")
        for r in m4["by_slot"]:
            L.append(f"    {r['bits_per_s']:5} bit/s: {r['wrong_bits']}/{r['bits_sent']} "
                     f"bits wrong ({r['wrong_pct']}%)")
    m4f = load("metric4_channel_fast.json")
    if m4f:
        L.append("Metric 4, faster speeds:")
        for r in m4f["by_slot"]:
            L.append(f"    {r['bits_per_s']:5} bit/s: {r['wrong_bits']}/{r['bits_sent']} "
                     f"bits wrong ({r['wrong_pct']}%)")
    if m5:
        L.append(f"Metric 5 (performance, average of {m5['runs_each']} runs): "
                 f"CPU {m5['cpu_events_per_s']} events/s, disk {m5['disk_iops']} IOPS "
                 f"({m5['disk_mb_per_s']} MB/s), network {m5['network_gbit_per_s']} Gbit/s")
    (d / "summary.txt").write_text("\n".join(L) + "\n", encoding="utf-8")
    say("\n".join(L))


FAST_SLOTS = [0.01, 0.005, 0.002]  # 100, 200, 500 bit/s


def cmd_fast(a):
    """metric 4 at higher speeds (saved as metric4_channel_fast.json)"""
    slots, tag = a.slots, a.tag
    a.slots, a.tag = FAST_SLOTS, "_fast"
    cmd_channel(a)
    a.slots, a.tag = slots, tag  # reset so perf etc. keep normal file names


# ---------------------------------------------------------------- misconfigured

SOCKET_QUERY = r"""
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect('/var/run/docker.sock')
s.sendall(b'GET /containers/json HTTP/1.0\r\nHost: docker\r\n\r\n')
body = b''
while True:
    chunk = s.recv(65536)
    if not chunk: break
    body += chunk
rows = json.loads(body.split(b'\r\n\r\n', 1)[1])
print(json.dumps([r['Names'][0].lstrip('/') for r in rows]))
"""


def cmd_misconfig(a):
    """privileged container and docker.sock container next to the tier 1
    victim, for comparison. read only."""
    d = HERE / "results" / "misconfig"
    d.mkdir(parents=True, exist_ok=True)
    res = {"collected": datetime.datetime.now().isoformat(timespec="seconds")}
    base = ["run", "--rm", "--network", "none", "--label", "project=cap5150-topic23"]
    rows = json.loads(docker(*base, "--privileged", IMAGE, "python3", "/lab/probe.py"))
    res["privileged_probe"] = {s: sum(r["status"] == s for r in rows)
                               for s in ("readable", "masked", "empty", "denied", "absent")}
    res["privileged_masked_files_now_readable"] = [
        r["file"] for r in rows if r["file"] in ("/proc/timer_list", "/proc/interrupts")
        and r["status"] == "readable"]
    # a privileged container can see the host's disks as device files
    res["privileged_host_block_devices"] = docker(
        *base, "--privileged", IMAGE, "sh", "-c", "ls /dev | grep -E '^(sd|vd|nvme)' || true"
    ).split()
    res["socket_sees_containers"] = json.loads(docker(
        *base, "-v", "/var/run/docker.sock:/var/run/docker.sock", IMAGE,
        "python3", "-c", SOCKET_QUERY))
    res["socket_sees_victim"] = VICTIM in res["socket_sees_containers"]
    (d / "misconfig.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    say(json.dumps(res, indent=2))


def cmd_all(a):
    for step in (cmd_up, cmd_env, cmd_check, cmd_probe, cmd_guess, cmd_channel,
                 cmd_fast, cmd_perf, cmd_audit, cmd_summary):
        say(f"\n===== {step.__name__[4:]} =====")
        step(a)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["build", "up", "env", "check", "probe", "guess",
                                     "channel", "fast", "perf", "audit", "summary",
                                     "misconfig", "all"])
    ap.add_argument("--tag", default="", help="suffix for the channel result file")
    ap.add_argument("--tier", type=int, choices=sorted(TIERS), default=1)
    ap.add_argument("--calib", type=int, default=5, help="labeled rounds per state")
    ap.add_argument("--trials", type=int, default=20, help="test rounds per state")
    ap.add_argument("--seconds", type=float, default=4, help="length of one round")
    ap.add_argument("--slots", type=lambda s: [float(x) for x in s.split(",")],
                    default=[0.5, 0.2, 0.1, 0.05, 0.02], help="slot lengths in seconds")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--nbits", type=int, default=128)
    ap.add_argument("--runs", type=int, default=3, help="repeats per benchmark")
    args = ap.parse_args()
    globals()[f"cmd_{args.step}"](args)

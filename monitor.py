import subprocess
from collections import defaultdict
import time
import json
from datetime import datetime, UTC
from pathlib import Path
import uuid
import os
import requests
import shutil
import platform
from detector import BaselineDetector
from host_info import get_host_info
import threading 
from live_info import start_process_monitor
from online_status import heartbeat_loop
from utils import iso_now
import ipaddress
from config import (
    ALERTS_DIR,
    ALERTS_URL,
    API_KEY,
    BASELINE_PATH,
    BPFTRACE_BIN,
    BPFTRACE_SCRIPT,
    DESTINATIONS_URL,
    HOSTS_URL,
    env_flag,
)
from logging_utils import get_logger


#this is the seconds for the detection time window
TIME_WINDOW = 5
# this is the runtime behaviour flags
IGNORE_LOCAL_TO_LOCAL = True
PRINT_EACH_EVENT = True
# this is the alert delivery and retry settings
ALERT_COOLDOWN_SECONDS = 45
DESTINATION_URL = DESTINATIONS_URL
MASTER_URL = ALERTS_URL
SEND_TO_MASTER = env_flag("DEFENSYS_SEND_TO_MASTER", True)
ALERT_RETRY_INTERVAL_SECONDS = 10
ALERT_RETRY_BATCH_SIZE = 25
RECENT_EXEC_MAX_AGE_SECONDS = 30
PENDING_ALERTS = []
logger = get_logger(__name__)

#this is the risk score bands for the alerts
RISK_LEVELS = {
    "medium": {"min": 5, "max": 7},
    "high": {"min": 8, "max": 10},
}
#default score for each rule
RULE_RISK_SCORES = {
    "EXEC_TMP": 8,
    "EXEC_THEN_CONNECT": 9,
    "POSSIBLE_REVERSE_SHELL": 10,
    "RATE_ANOMALY": 5,
    "UNIQUE_PORTS_ANOMALY": 6,
    "REPEAT_ENDPOINT_ANOMALY": 5,
    "UNIQUE_IPS_ANOMALY": 6,
    "FANOUT_RATIO_ANOMALY": 7,
}

#returns true for the routable public IPs
def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except ValueError:
        return False
#converts the numeric risk score into a label
def score_to_level(score: int) -> str | None:
    if RISK_LEVELS["high"]["min"] <= score <= RISK_LEVELS["high"]["max"]:
        return "high"
    if RISK_LEVELS["medium"]["min"] <= score <= RISK_LEVELS["medium"]["max"]:
        return "medium"
    return None
#adds the risk score and level to the alert
def apply_risk(alert: dict, rule_key: str, extra_score: int = 0) -> dict:
    base = RULE_RISK_SCORES.get(rule_key, 5)
    score = max(0, min(10, base + extra_score))
    alert["risk_score"] = score
    alert["risk_level"] = score_to_level(score)
    return alert
#prevents duplicate alerts from occuring in a given timeframe
def should_emit_alert(state, rule, comm, pid, now):
    key = (rule, comm, int(pid))
    last_time = state["last_alert_time"].get(key)

    if last_time is not None and (now - last_time) < ALERT_COOLDOWN_SECONDS:
        return False

    state["last_alert_time"][key] = now
    return True

#starts the bpftrace sctips that streams the exec/network events
def start_bpftrace():
    if platform.system() != "Linux":
        raise RuntimeError("bpftrace monitoring is only supported on Linux hosts.")

    if shutil.which(BPFTRACE_BIN) is None:
        raise RuntimeError(
            f"'{BPFTRACE_BIN}' was not found in PATH. Install bpftrace or set DEFENSYS_BPFTRACE_BIN."
        )

    if not BPFTRACE_SCRIPT.exists():
        raise RuntimeError(
            f"bpftrace script not found at {BPFTRACE_SCRIPT}. Set DEFENSYS_BPFTRACE_SCRIPT to the correct file."
        )

    return subprocess.Popen(
        [BPFTRACE_BIN, str(BPFTRACE_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

#filnames that are string safe
def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in s)[:60]

#stores the alerts as a local JSON
def write_alert_to_new_file(alert: dict, host_info: dict) -> str:
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    alert["host"] = host_info
    if alert.get("example_event") is None:
        alert["example_event"] = {}

    rnd = uuid.uuid4().hex[:8]

    filename = f"alert_{rnd}.json"
    path = ALERTS_DIR / filename

    with open(path, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)
        f.write("\n")

    return str(path)

#saves host metadata locally
def write_host_info_file(host_info: dict) -> str:
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"host_info_{ts}.json"
    path = ALERTS_DIR / filename

    with open(path, "w", encoding="utf-8") as f:
        json.dump(host_info, f, indent=2)
        f.write("\n")

    logger.debug("Wrote host info to %s", path)
    return str(path)

#sends the alert to the master API
def send_alert_to_master(alert: dict, host_info: dict, *, log_failure: bool = True) -> bool:
    payload = dict(alert)
    payload["host"] = host_info

    if payload.get("example_event") is None:
        payload["example_event"] = {}

    try:
        r = requests.post(
            MASTER_URL,
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        logger.debug("Alert POST status=%s body=%s", r.status_code, r.text.strip())
        r.raise_for_status()
    except requests.exceptions.RequestException as exc:
        if log_failure:
            logger.exception(
                "Failed to POST alert rule=%s pid=%s to %s",
                payload.get("rule"),
                payload.get("pid"),
                MASTER_URL,
            )
        else:
            logger.debug(
                "Pending alert still cannot be delivered rule=%s pid=%s to %s: %s",
                payload.get("rule"),
                payload.get("pid"),
                MASTER_URL,
                exc,
            )
        return False

    if r.content:
        try:
            response_json = r.json()
            logger.debug("Alert POST response JSON keys=%s", sorted(response_json.keys()))
        except ValueError:
            logger.debug("Alert POST response was not JSON")

    return True

#writes the alert locally and then tries to send it
def emit_alert(alert: dict, host_info: dict) -> str:
    path = write_alert_to_new_file(alert, host_info)

    if not SEND_TO_MASTER:
        logger.debug("Alert saved locally only because DEFENSYS_SEND_TO_MASTER is false: %s", path)
        return path

    if not send_alert_to_master(alert, host_info):
        PENDING_ALERTS.append(dict(alert))
        logger.warning("Alert delivery queued in memory for retry: %s", path)

    return path

#retries the unsent alerts
def retry_pending_alerts(host_info: dict) -> None:
    if not PENDING_ALERTS:
        return

    for payload in PENDING_ALERTS[:ALERT_RETRY_BATCH_SIZE]:
        if send_alert_to_master(payload, host_info, log_failure=False):
            PENDING_ALERTS.remove(payload)
            logger.debug(
                "Retried alert delivery succeeded rule=%s pid=%s",
                payload.get("rule"),
                payload.get("pid"),
            )

#rbackground retry loop for the alerts that faoled to deliver
def alert_retry_loop(host_info: dict) -> None:
    while True:
        if SEND_TO_MASTER:
            retry_pending_alerts(host_info)
        time.sleep(ALERT_RETRY_INTERVAL_SECONDS)

# sends the observed destination details to the master api
def send_destination_to_master(host_info, comm, pid, dst_ip, dst_port, src_ip=None, src_port=None):
    payload = {
        "ts": iso_now(),
        "host_id": host_info["host_id"],
        "hostname": host_info.get("hostname"),
        "comm": comm,
        "pid": int(pid),
        "src_ip": src_ip,
        "src_port": int(src_port) if src_port is not None else None,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),
    }

    try:
        requests.post(
            DESTINATION_URL,
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
    except requests.exceptions.RequestException:
        pass

#sends host metadata to the master api
def send_host_to_master(host_info):
    try:
        r = requests.post(
            HOSTS_URL,
            json=host_info,
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        logger.debug("Host POST status=%s body=%s", r.status_code, r.text.strip())

    except requests.exceptions.RequestException as e:
        logger.exception("Failed to send host info")

#clears every window after analysis
def reset_window(state, now):
    state["window_start"] = now
    state["conn_count_by_proc"].clear()
    state["unique_ports_by_proc"].clear()
    state["endpoint_hits"].clear()
    state["unique_ips_by_proc"].clear()
    state["example_event_by_proc"].clear()
    state["alerted_rate"].clear()
    state["alerted_scan"].clear()
    state["alerted_repeat"].clear()
    state["sent_destinations_this_window"].clear()

#removes old exec events from memory
def prune_recent_exec(state, now: float) -> None:
    stale_pids = [
        pid for pid, info in state["recent_exec"].items()
        if (now - info["time"]) > RECENT_EXEC_MAX_AGE_SECONDS
    ]
    for pid in stale_pids:
        state["recent_exec"].pop(pid, None)


def main():
    #starts the live proess tracking thread
    threading.Thread(target=start_process_monitor,daemon=True).start()

#collects and sends host identity
    HOST_INFO = get_host_info()
    write_host_info_file(HOST_INFO)
    send_host_to_master(HOST_INFO)
#starts background sttaus and retry workers
    threading.Thread(target=heartbeat_loop, args=(HOST_INFO,), daemon=True).start()
    threading.Thread(target=alert_retry_loop, args=(HOST_INFO,), daemon=True).start()


    HEARTBEAT_INTERVAL = 10
    last_heartbeat = 0

#dynamic baseline detector for anomaly rules
    detector = BaselineDetector (
        percentile=99.0,
        threshold_mode="mad",
        mad_k=3.5,
        baseline_pathway=str(BASELINE_PATH),
        time_window=TIME_WINDOW,
        window_history=50,
        warmup_windows=15,
        learn_anomalies=False,
        key_mode="comm", 
    )
    
    detector.load()

#shares runtime stat efor the current window
    state = {
        "window_start": time.time(),
        "conn_count_by_proc": defaultdict(int),
        "unique_ports_by_proc": defaultdict(set),
        "unique_ips_by_proc": defaultdict(set),
        "endpoint_hits": defaultdict(int),
        "example_event_by_proc": {},
        "alerted_rate": set(),
        "alerted_scan": set(),
        "alerted_repeat": set(),
        "recent_exec": {},
        "sent_destinations_this_window": set(),
        "last_alert_time": {},
    }

    logger.debug("Starting bpftrace connection monitor")
    logger.debug("Local alert files will be written into: %s", ALERTS_DIR)
    logger.debug("Master URL: %s (send=%s)", MASTER_URL, SEND_TO_MASTER)
    logger.debug("RATE rule: dynamic baseline (median/MAD)")


    proc = start_bpftrace()
    logger.debug("Waiting for events")

    def close_window(now: float):
#runs the baseline checks at the end of each window
        for (comm, pid), count in state["conn_count_by_proc"].items():
            example_event = state["example_event_by_proc"].get((comm, pid))
            
            alert, thr = detector.update(
                metric="rate",
                comm=comm,
                pid=int(pid),
                value=count,
                example_event=example_event,
                rule_name="RATE_ANOMALY",
                min_delta=2,
                relative_margin=0.20,
            )

            if alert and should_emit_alert(state, "RATE_ANOMALY", comm, pid, now):
                alert = apply_risk(alert, "RATE_ANOMALY")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("RATE dynamic alert wrote %s", path)

        for (comm, pid), ports in state["unique_ports_by_proc"].items():
            unique_count = len(ports)
            example_event = state["example_event_by_proc"].get((comm, pid))
            alert, thr = detector.update(
                metric="unique_ports",
                comm=comm,
                pid=int(pid),
                value=unique_count,
                example_event=example_event,
                rule_name="UNIQUE_PORTS_ANOMALY",
                min_delta=1,
            )
            if alert:
                alert["unique_dst_ports"] = sorted(int(p) for p in ports)
                alert = apply_risk(alert, "UNIQUE_PORTS_ANOMALY")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("PORTS dynamic alert wrote %s", path)

#finds the most repeated endpoint per process
        max_by_proc = {}
        for (comm, pid, dst_ip, dst_port), hits in state["endpoint_hits"].items():
            pid_i = int(pid)
            if (comm, pid_i) not in max_by_proc or hits > max_by_proc[(comm, pid_i)][0]:
                max_by_proc[(comm, pid_i)] = (hits, dst_ip, dst_port)

        for (comm, pid_i), (max_hits, dst_ip, dst_port) in max_by_proc.items():
            alert, thr = detector.update(
                metric="repeat_endpoint",
                comm=comm,
                pid=pid_i,
                value=max_hits,
                rule_name="REPEAT_ENDPOINT_ANOMALY",
                min_delta=2,
                relative_margin=0.20,
            )
            if alert:
                alert["dst_ip"] = dst_ip
                alert["dst_port"] = int(dst_port)
                alert["hits"] = int(max_hits)
                alert = apply_risk(alert, "REPEAT_ENDPOINT_ANOMALY")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("REPEAT dynamic alert wrote %s", path)

        for (comm, pid), ips in state["unique_ips_by_proc"].items():
            unique_ip_count = len(ips)

            alert, thr = detector.update(
                metric="unique_ips",
                comm=comm,
                pid=int(pid),
                value=unique_ip_count,
                rule_name="UNIQUE_IPS_ANOMALY",
                min_delta=1,
            )

            if alert:
                alert["unique_dst_ips"] = list(ips)
                alert = apply_risk(alert, "UNIQUE_IPS_ANOMALY")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("IPS dynamic alert wrote %s", path)
                #fanout ratio checks whether the conections spreaded across many IPs
            total = state["conn_count_by_proc"].get((comm, pid), 0)
            if total > 0:
                fanout_ratio = unique_ip_count / total

                alert, thr = detector.update(
                    metric="fanout_ratio",
                    comm=comm,
                    pid=int(pid),
                    value=fanout_ratio,
                    rule_name="FANOUT_RATIO_ANOMALY",
                    min_delta=0.05,
                    relative_margin=0.25,
                )

                if alert:
                    alert["fanout_ratio"] = fanout_ratio
                    alert = apply_risk(alert, "FANOUT_RATIO_ANOMALY")
                    path = emit_alert(alert, HOST_INFO)
                    logger.debug("FANOUT dynamic alert wrote %s", path)
        detector.save()
        reset_window(state, now)

#main event loup that pares bpftrace output line by line
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        # print ("[RAW]", repr (line))

        if "ERROR:" in line:
            logger.error("bpftrace error: %s", line)
            continue

        if line.startswith("Attaching") or line.startswith("ts_ns,"):
            continue

        cols = line.split(",")
        if len(cols) < 2:
            continue

        direction = cols[1]

        now = time.time()
        prune_recent_exec(state, now)
#EXEC events that record the newly executed binaries
        if direction == "EXEC":
            if len(cols) < 5:
                logger.debug("Dropped malformed EXEC line: %s", line)
                continue

            ts_ns, direction, exec_path, pid, comm = cols[:5]
            logger.debug("exec %s(%s) path=%s", comm, pid, exec_path)
            
            state["recent_exec"][pid] = {
                "path": exec_path,
                "time": now 
            }
        #executing from writable temp locations being suspicious
            if exec_path.startswith("/tmp") or exec_path.startswith("/dev/shm"):
                alert = {
                    "ts": iso_now(),
                    "rule": "EXEC_TMP",
                    "comm": comm,
                    "pid": int(pid),
                    "example_event":{
                        "path": exec_path
                    }
                }
                alert = apply_risk(alert, "EXEC_TMP")

                path = emit_alert(alert, HOST_INFO)
                logger.debug("EXEC_TMP alert wrote %s", path)

            continue

        if len(cols) < 9:
            logger.debug("Dropped malformed line: %s", line)
            continue

        ts_ns, direction, src_ip, src_port, dst_ip, dst_port, comm, pid, ret = cols[:9]

        if IGNORE_LOCAL_TO_LOCAL and src_ip == dst_ip:
            continue

        if direction != "OUT":
            continue

        if now - state["window_start"] >= TIME_WINDOW:
            close_window(now)

        if PRINT_EACH_EVENT:
            logger.debug(
                "event %s %s(%s) %s:%s -> %s:%s ret=%s",
                direction,
                comm,
                pid,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                ret,
            )

        proc_key = (comm, pid)
        exec_info = state["recent_exec"].get(pid)

#detects temp execution followed by a network connection
        if exec_info and now - exec_info["time"] < 5:
            if exec_info["path"].startswith("/tmp"):
                alert = {
                    "ts": iso_now(),
                    "rule": "EXEC_THEN_CONNECT",
                    "comm": comm,
                    "pid": int(pid),
                    "example_event": {
                        "exec_path": exec_info["path"],
                        "dst_ip": dst_ip,
                        "dst_port": int(dst_port)
                    }
                }
                alert = apply_risk(alert, "EXEC_THEN_CONNECT")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("EXEC_THEN_CONNECT alert wrote %s", path)

#shell process connecting soon after an exec
        if exec_info and "sh" in exec_info["path"]:
            if now - exec_info["time"] < 3:
                alert = {
                    "ts": iso_now(),
                    "rule": "POSSIBLE_REVERSE_SHELL",
                    "comm": comm,
                    "pid": int(pid),
                    "example_event": {
                        "exec": exec_info["path"],
                        "dst_ip": dst_ip
                    }
                }
                alert = apply_risk(alert, "POSSIBLE_REVERSE_SHELL")
                path = emit_alert(alert, HOST_INFO)
                logger.debug("POSSIBLE_REVERSE_SHELL alert wrote %s", path)

#save first example event for later alert conetxt
        if proc_key not in state["example_event_by_proc"]:
            state["example_event_by_proc"][proc_key] = {
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "direction": direction,
                "ret": int(ret),
            }

    #update per process metrics for the current window
        state["conn_count_by_proc"][proc_key] += 1
        state["unique_ports_by_proc"][proc_key].add(dst_port)
        state["unique_ips_by_proc"][proc_key].add(dst_ip) 

        destination_key = (dst_ip, dst_port, comm, pid)

#sends each destination once per window
        if destination_key not in state["sent_destinations_this_window"]:
            send_destination_to_master(
                HOST_INFO,
                comm=comm,
                pid=pid,
                dst_ip=dst_ip,
                dst_port=dst_port,
                src_ip=src_ip,
                src_port=src_port,
            )
            state["sent_destinations_this_window"].add(destination_key)
            logger.debug("Destination %s public=%s", dst_ip, is_public_ip(dst_ip))

#count repoeated connections to the same endpoint
        ep_key = (comm, pid, dst_ip, dst_port)
        state["endpoint_hits"][ep_key] += 1


if __name__ == "__main__":

    main()
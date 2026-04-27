import time
from datetime import datetime, UTC

import psutil
import requests

from config import API_KEY, PROCESS_ACTIVITY_URL, env_flag
from host_info import get_host_info
from logging_utils import get_logger


# process activity endpoint/settings.
PROCESS_URL = PROCESS_ACTIVITY_URL
SEND_TO_MASTER = env_flag("DEFENSYS_SEND_TO_MASTER", True)
TOP_N = 15
INTERVAL_SECONDS = 1
logger = get_logger(__name__)


def iso_now():
    # current local timestamp.
    return datetime.now().astimezone().isoformat(timespec="seconds")


def calculate_activity_score(cpu_percent: float, memory_mb: float, network_events: int = 0) -> float:
    # calculates bubble size/activity score.
    score = (cpu_percent * 1.5) + (memory_mb * 0.02) + (network_events * 3)
    return round(score, 2)


def warm_up_cpu_counters():
    # primes psutil CPU counters.
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


def get_process_snapshot():
    # collects current CPU and memory usage.
    processes = []

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or "unknown"
            cpu_percent = proc.info["cpu_percent"] or 0.0

            memory_info = proc.info["memory_info"]
            memory_mb = (memory_info.rss / (1024 * 1024)) if memory_info else 0.0

            processes.append({
                "pid": pid,
                "name": name,
                "cpu_percent": round(cpu_percent, 2),
                "memory_mb": round(memory_mb, 2),
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes


def build_top_processes(raw_processes, top_n=TOP_N):
    # groups processes by name and ranks them by activity.
    grouped = {}

    for proc in raw_processes:
        name = proc["name"] or "unknown"
        network_events = 0

        activity_score = calculate_activity_score(
            cpu_percent=proc["cpu_percent"],
            memory_mb=proc["memory_mb"],
            network_events=network_events,
        )

        if activity_score <= 0:
            continue

        if name not in grouped:
            grouped[name] = {
                "name": name,
                "process_count": 0,
                "cpu_percent": 0.0,
                "memory_mb": 0.0,
                "network_events": 0,
                "activity_score": 0.0,
                "pids": [],
            }

        grouped[name]["process_count"] += 1
        grouped[name]["cpu_percent"] += proc["cpu_percent"]
        grouped[name]["memory_mb"] += proc["memory_mb"]
        grouped[name]["network_events"] += network_events
        grouped[name]["activity_score"] += activity_score
        grouped[name]["pids"].append(proc["pid"])

    output = list(grouped.values())

    # round totals for clean output.
    for proc in output:
        proc["cpu_percent"] = round(proc["cpu_percent"], 2)
        proc["memory_mb"] = round(proc["memory_mb"], 2)
        proc["activity_score"] = round(proc["activity_score"], 2)

    output.sort(key=lambda p: p["activity_score"], reverse=True)
    return output[:top_n]


def send_process_activity(payload):
    # sends process activity to master API.
    try:
        response = requests.post(
            PROCESS_URL,
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=5,
        )
        logger.debug(
            "Process activity POST status=%s body=%s",
            response.status_code,
            response.text.strip(),
        )
    except requests.exceptions.RequestException:
        logger.exception("Failed to send process activity")


def start_process_monitor():
    # main monitoring loop.
    host_info = get_host_info()
    host_id = host_info["host_id"]

    warm_up_cpu_counters()
    time.sleep(1)

    while True:
        raw_processes = get_process_snapshot()
        top_processes = build_top_processes(raw_processes, top_n=TOP_N)

        payload = {
            "host_id": host_id,
            "ts": iso_now(),
            "processes": top_processes,
        }

        logger.debug("Process payload contains %s grouped processes", len(top_processes))

        if SEND_TO_MASTER:
            send_process_activity(payload)

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    start_process_monitor()
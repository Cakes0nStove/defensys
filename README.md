# Defensys Agent

Defensys Agent is a Linux monitoring agent that watches process execution and outbound TCP connections with `bpftrace`, scores suspicious activity, writes local alert JSON files, and posts host, heartbeat, process activity, destinations, and alerts to the Defensys master API.

## What It Detects

The current rules are:

- `EXEC_TMP`: executable launched from `/tmp` or `/dev/shm`
- `EXEC_THEN_CONNECT`: process executed from `/tmp` and quickly made an outbound connection
- `POSSIBLE_REVERSE_SHELL`: process path containing `sh` made an outbound connection shortly after execution
- `RATE_ANOMALY`: unusual connection rate for a process
- `UNIQUE_PORTS_ANOMALY`: unusual number of destination ports
- `REPEAT_ENDPOINT_ANOMALY`: repeated hits to the same destination endpoint
- `UNIQUE_IPS_ANOMALY`: unusual number of destination IPs
- `FANOUT_RATIO_ANOMALY`: unusual IP fanout compared with total connections

Risk scores are configured in `monitor.py` in `RULE_RISK_SCORES`.

## Requirements

This agent is intended for Linux. It needs:

- Python 3
- `bpftrace`
- permission to access kernel tracing, usually by running the agent with `sudo`
- a reachable Defensys master API

Install system packages on Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip bpftrace linux-headers-$(uname -r)
```

If tracing is not mounted:

```bash
sudo mount -t tracefs nodev /sys/kernel/tracing
sudo mount -t debugfs nodev /sys/kernel/debug
```

## Setup

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create or edit `.env`:

```env
Refer to the user guide
```

Replace `YOUR_MASTER_SERVER_IP` with the machine running the backend API used by the frontend.

## Fresh Baseline

For a completely new baseline before first run, `baseline.json` can be:

```json
{}
```

The agent will populate the baseline automatically after it runs.

## Run

Run the agent with the virtual environment Python and `sudo`:

```bash
sudo -E .venv/bin/python monitor.py
```

The `-E` preserves environment behavior, and the project also loads `.env` from the project directory.

## Test Alerts

With `monitor.py` running, open another terminal and run:

```bash
source .venv/bin/activate
python trigger_alerts.py
```

The trigger script attempts to exercise all alert rules using benign test connection attempts and temporary executable paths.

Dynamic baseline alerts may require an existing warmed baseline. If dynamic rules do not fire immediately, run the trigger again or test after the baseline has collected enough windows.

## bpftrace Checks

Check required probes:

```bash
sudo bpftrace -l 'tracepoint:syscalls:*execve*'
sudo bpftrace -l 'tracepoint:syscalls:*connect*'
sudo bpftrace -l 'kprobe:tcp_v4_connect'
```

Test the bpftrace script directly:

```bash
sudo bpftrace ./custom_script.bt
```

In another terminal:

```bash
python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('1.1.1.1', 443))"
```

Expected output shape:

```text
ts_ns,direction,src_ip,src_port,dst_ip,dst_port,comm,pid,ret
123456789,OUT,10.0.0.x,54321,1.1.1.1,443,python3,1234,0
```

If `custom_script.bt` fails on a VM but works on a laptop, the VM likely has different kernel headers, BTF support, or tracing permissions. This repo's `custom_script.bt` avoids Linux header includes to reduce VM compatibility problems.

## Alert Files

Alerts are written to:

```text
alerts/alert_*.json
```

The agent no longer writes `.sent` or `.pending` marker files. Failed alert deliveries are retried in memory while the agent is still running.

To clean old marker files from an older version:

```bash
find alerts \( -name '*.sent' -o -name '*.pending' \) -delete
```

## Troubleshooting

If the frontend does not receive alerts, check the master API:

```bash
curl -i http://YOUR_MASTER_SERVER_IP:8000/alerts
```

If host, heartbeat, and process activity work but alerts do not, check whether `bpftrace` is emitting event rows:

```bash
sudo bpftrace ./custom_script.bt
```

If you see kernel permission errors, run the agent with `sudo`.

If you see bpftrace compile errors, verify the probes listed above and make sure you are using the `custom_script.bt` included in this repo.
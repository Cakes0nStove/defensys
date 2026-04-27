import socket
import uuid
import platform
import getpass
import hashlib
from datetime import datetime
from pathlib import Path


def iso_now():
    # current local timestamp.
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_real_ip():
    # finds the main outbound local IP.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "unknown"
    finally:
        s.close()

    return ip


def get_host_info():
    # collects host identity, network, and system data.
    hostname = socket.gethostname()
    ip = get_real_ip()
    user = getpass.getuser()

    # build MAC address.
    mac = ":".join(
        f"{(uuid.getnode() >> ele) & 0xff:02x}"
        for ele in range(40, -1, -8)
    )

    # prefer stable Linux machine ID.
    machine_id = None
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(candidate).read_text(encoding="utf-8").strip()
            if value:
                machine_id = value
                break
        except OSError:
            continue

    # fallback ID if machine ID is unavailable.
    if not machine_id:
        machine_id = f"{platform.node()}:{mac}:{user}"

    # short anonymous host identifier.
    host_id = hashlib.sha256(machine_id.encode("utf-8")).hexdigest()[:12]

    # basic /24 network ID.
    if ip != "unknown":
        parts = ip.split(".")
        network_id = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    else:
        network_id = "unknown"

    # system info.
    os_name = platform.system()
    os_version = platform.release()
    architecture = platform.machine()

    # agent start time.
    started_at = iso_now()

    return {
        # identity.
        "host_id": host_id,
        "hostname": hostname,
        "user": user,

        # network.
        "local_ip": ip,
        "mac_address": mac,
        "network_id": network_id,

        # system.
        "os": os_name,
        "os_version": os_version,
        "architecture": architecture,

        # agent metadata.
        "agent_type": "defensys-agent",
        "agent_version": "1.0",
        "started_at": started_at,

        # runtime state.
        "status": "ONLINE",
        "last_seen": iso_now(),
    }
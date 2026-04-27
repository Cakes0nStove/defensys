import requests
from utils import iso_now
import time
from config import API_KEY, HEARTBEAT_URL
from logging_utils import get_logger


# heartbeat timing/settings.
HEARTBEAT_INTERVAL = 10
logger = get_logger(__name__)


def send_heartbeat_to_master(host_info):
    # sends current host status to master API.
    payload = {
        "ts": iso_now(),
        "host_id": host_info["host_id"],
        "hostname": host_info.get("hostname"),
        "status": "online",
    }

    try:
        response = requests.post(
            HEARTBEAT_URL,
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=5,
        )
        logger.debug("Heartbeat POST status=%s", response.status_code)

    except requests.exceptions.RequestException:
        logger.exception("Failed to send heartbeat")


def heartbeat_loop(host_info):
    # sends heartbeat repeatedly.
    while True:
        send_heartbeat_to_master(host_info)
        time.sleep(HEARTBEAT_INTERVAL)
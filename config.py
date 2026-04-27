import os
from pathlib import Path


# base folder for this config file.
BASE_DIR = Path(__file__).resolve().parent


def load_dotenv(path: Path) -> None:
    # loads simple key/value pairs from a .env file.
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        # skip empty lines, comments, and invalid lines.
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")

        # Do not overwrite existing environment variables.
        os.environ.setdefault(key, value)


# load local environment settings.
load_dotenv(BASE_DIR / ".env")


# data storage paths.
DATA_DIR = Path(os.getenv("DEFENSYS_DATA_DIR", str(BASE_DIR))).expanduser()

DEFAULT_MASTER_BASE_URL = "http://127.0.0.1:8000"
MASTER_BASE_URL = os.getenv("DEFENSYS_MASTER_BASE_URL", DEFAULT_MASTER_BASE_URL).rstrip("/")

# API and logging settings.
API_KEY = os.getenv("DEFENSYS_API_KEY", "secret")
LOG_LEVEL = os.getenv("DEFENSYS_LOG_LEVEL", "ERROR").upper()


# local alert and baseline files.
ALERTS_DIR = Path(
    os.getenv("DEFENSYS_ALERTS_DIR", str(DATA_DIR / "alerts"))
).expanduser()

BASELINE_PATH = Path(
    os.getenv("DEFENSYS_BASELINE_PATH", str(DATA_DIR / "baseline.json"))
).expanduser()


# bpftrace settings.
BPFTRACE_SCRIPT = Path(
    os.getenv("DEFENSYS_BPFTRACE_SCRIPT", str(BASE_DIR / "custom_script.bt"))
).expanduser()

BPFTRACE_BIN = os.getenv("DEFENSYS_BPFTRACE_BIN", "bpftrace")


# master API endpoints.
HOSTS_URL = f"{MASTER_BASE_URL}/hosts"
ALERTS_URL = f"{MASTER_BASE_URL}/alerts"
DESTINATIONS_URL = f"{MASTER_BASE_URL}/destinations"
HEARTBEAT_URL = f"{MASTER_BASE_URL}/heartbeat"
PROCESS_ACTIVITY_URL = f"{MASTER_BASE_URL}/process-activity"


def env_flag(name: str, default: bool) -> bool:
    # reads boolean-like environment variables.
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}
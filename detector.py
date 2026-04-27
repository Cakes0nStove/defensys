import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timezone
import re
import numpy as np
from config import BASELINE_PATH
from logging_utils import get_logger

logger = get_logger(__name__)


def dumps_compact_lists(obj):
    # pretty json, but keeps numeric lists short.
    text = json.dumps(obj, indent=2)

    def collapse(match):
        content = match.group(1)
        nums = [x.strip() for x in content.split(",") if x.strip()]
        return "[" + ", ".join(nums) + "]"

    text = re.sub(
        r"\[\s*([\d\.\,\s\-]+?)\s*\]",
        collapse,
        text,
        flags=re.MULTILINE
    )

    return text


class BaselineDetector:
    # tracks normal behaviour and detects metric spikes.

    def __init__(
        self,
        *,
        percentile: float = 99.0,
        threshold_mode: str = "percentile",
        mad_k: float = 3.5,
        baseline_pathway: str = str(BASELINE_PATH),
        time_window: int = 5,
        window_history: int = 200,
        warmup_windows: int = 20,
        learn_anomalies: bool = False,
        key_mode: str = "comm",
        debug: bool = False,
    ):
        # Store detector settings.
        self.percentile = float(percentile)
        self.threshold_mode = str(threshold_mode)
        self.mad_k = float(mad_k)
        self.baseline_path = Path(baseline_pathway)
        self.time_window = int(time_window)
        self.window_history = int(window_history)
        self.warmup_windows = int(warmup_windows)
        self.learn_anomalies = bool(learn_anomalies)
        self.key_mode = key_mode
        self.debug = bool(debug)

        # metric history per process/key.
        self.hist = defaultdict(lambda: deque(maxlen=self.window_history))

    @staticmethod
    def _coerce_value(value: int | float) -> int | float:
        # keeps saved values tidy.
        number = float(value)
        if number.is_integer():
            return int(number)
        return round(number, 4)

    def _percentile_threshold(self, values) -> float:
        # calculates percentile-based threshold.
        arr = np.asarray(values, dtype=np.float64)
        try:
            return float(np.percentile(arr, self.percentile, method="higher"))
        except TypeError:
            return float(np.percentile(arr, self.percentile, interpolation="higher"))

    @staticmethod
    def _minimum_step(arr: np.ndarray) -> float:
        # finds a safe minimum spread for MAD.
        unique = np.unique(arr)
        if unique.size > 1:
            diffs = np.diff(np.sort(unique))
            positive = diffs[diffs > 0]
            if positive.size:
                return float(np.min(positive))

        med = float(np.median(arr))
        if med >= 1.0:
            return 1.0
        return 0.01

    def _mad_threshold(self, values) -> float:
        # calculates robust MAD-based threshold.
        arr = np.asarray(values, dtype=np.float64)
        med = float(np.median(arr))
        deviations = np.abs(arr - med)
        mad = float(np.median(deviations))

        robust_sigma = 1.4826 * mad
        floor = self._minimum_step(arr)
        robust_sigma = max(robust_sigma, floor)
        return med + (self.mad_k * robust_sigma)

    def iso_now(self) -> str:
        # current local timestamp.
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    def make_key(self, comm: str, pid: int) -> str:
        # chooses how process history is grouped.
        if self.key_mode == "comm":
            return comm
        if self.key_mode == "comm_pid":
            return f"{comm}:{pid}"
        raise ValueError(f"Unknown key_mode: {self.key_mode}")

    def hist_key(self, metric: str, comm: str, pid: int) -> str:
        # full key for one metric/process pair.
        return f"{metric}|{self.make_key(comm, pid)}"

    def load(self) -> None:
        # loads saved baseline history.
        if not self.baseline_path.exists():
            return

        raw_text = self.baseline_path.read_text(encoding="utf-8").strip()
        if not raw_text:
            return

        data = json.loads(raw_text)
        raw = data.get("hist", {})

        self.hist.clear()
        for k, values in raw.items():
            self.hist[k] = deque(values, maxlen=self.window_history)

    def save(self) -> None:
        # writes baseline history to disk.
        if self.debug:
            logger.debug("BASELINE DEBUG")
            if not self.hist:
                logger.debug("baseline empty")
            else:
                for k, dq in self.hist.items():
                    logger.debug("Key: %s", k)
                    logger.debug("Values: %s", list(dq))
                    logger.debug("Windows stored: %s", len(dq))
                    if len(dq) >= self.warmup_windows:
                        thr = self.threshold(k)
                        logger.debug("Dynamic threshold (%s): %s", self.threshold_mode, thr)

        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "hist": {k: list(dq) for k, dq in self.hist.items()},
            "meta": {
                "saved_at": self.iso_now(),
                "time_window": self.time_window,
                "window_history": self.window_history,
                "warmup_windows": self.warmup_windows,
                "threshold_mode": self.threshold_mode,
                "percentile": self.percentile,
                "mad_k": self.mad_k,
                "learn_anomalies": self.learn_anomalies,
                "key_mode": self.key_mode,
            },
        }

        self.baseline_path.write_text(
            dumps_compact_lists(payload) + "\n",
            encoding="utf-8"
        )

    def threshold(self, hist_key: str) -> float | None:
        # returns current threshold if enough history exists.
        dq = self.hist.get(hist_key)
        if not dq or len(dq) < self.warmup_windows:
            return None

        if self.threshold_mode == "percentile":
            return self._percentile_threshold(dq)

        if self.threshold_mode == "mad":
            return self._mad_threshold(dq)

        raise ValueError(f"Unknown threshold_mode: {self.threshold_mode}")

    @staticmethod
    def _threshold_with_margin(
        threshold: float,
        *,
        min_delta: int | float = 0,
        relative_margin: float = 0.0,
    ) -> float:
        # adds absolute or relative buffer to threshold.
        threshold = float(threshold)
        min_delta = float(min_delta)
        relative_margin = float(relative_margin)

        return max(
            threshold + min_delta,
            threshold * (1.0 + relative_margin)
        )

    def update(
        self,
        *,
        metric: str,
        comm: str,
        pid: int,
        value: int | float,
        example_event: dict | None = None,
        compare: str = ">",
        rule_name: str | None = None,
        min_delta: int | float = 0,
        relative_margin: float = 0.0,
    ) -> tuple[dict | None, float | None]:
        # adds a new value and returns an alert if anomalous.

        hk = self.hist_key(metric, comm, pid)
        dq = self.hist[hk]
        numeric_value = self._coerce_value(value)

        base_thr = self.threshold(hk)

        if base_thr is None:
            thr = None
            is_anomaly = False
        else:
            thr = self._threshold_with_margin(
                base_thr,
                min_delta=min_delta,
                relative_margin=relative_margin,
            )

            if compare == ">":
                is_anomaly = numeric_value > thr
            elif compare == ">=":
                is_anomaly = numeric_value >= thr
            else:
                raise ValueError("compare must be '>' or '>='")

        alert = None

        if is_anomaly:
            alert = {
                "ts": self.iso_now(),
                "rule": rule_name or f"{metric.upper()}_DYNAMIC",
                "metric": metric,
                "window_s": self.time_window,
                "threshold": float(thr),
                "baseline_threshold": float(base_thr),
                "threshold_mode": self.threshold_mode,
                "percentile": self.percentile,
                "mad_k": self.mad_k,
                "comm": comm,
                "pid": int(pid),
                "value": numeric_value,
                "key": hk,
                "example_event": example_event,
            }

        # learn only normal values unless configured otherwise.
        if (not is_anomaly) or self.learn_anomalies:
            dq.append(numeric_value)

        return alert, thr
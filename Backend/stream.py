# stream.py
import time
import os
from typing import Iterator, Optional

class StreamEngine:
    """
    Tail the Zeek conn.log (tab separated). Provide:
      - stream_lines(): generator yielding new lines as they appear
      - line_to_record(line): parse a conn.log line into a dict
    """

    def __init__(self, zeek_dir: str):
        self.zeek_dir = zeek_dir
        self.conn_path = os.path.join(zeek_dir, "conn.log")

    def stream_lines(self, sleep=0.5) -> Iterator[str]:
        """Yield new lines appended to conn.log (robust tail -f)."""
        while True:
            # wait for file to exist
            while not os.path.exists(self.conn_path):
                time.sleep(1)

            try:
                with open(self.conn_path, "r", errors="ignore") as f:
                    # start tailing from end
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(sleep)
                            continue
                        line = line.rstrip("\n")
                        if line.startswith("#"):
                            continue
                        yield line
            except Exception:
                # file rotated / replaced / temporarily unavailable
                time.sleep(1)



    def _safe_float(self, v, default=0.0):
        try:
            return float(v) if v not in ("", "-", None) else default
        except Exception:
            return default

    def _safe_int(self, v, default=0):
        try:
            return int(v) if v not in ("", "-", None) else default
        except Exception:
            return default

    def line_to_record(self, line: str) -> Optional[dict]:
        """Parse Zeek conn.log formatted line to a normalized record dict."""
        parts = line.split("\t")
        # Zeek conn.log typical columns are many; to be robust map by positions.
        # We'll guard against indexing errors.
        try:
            # very commonly: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig_pkts, local_resp_pkts...
            ts = self._safe_float(parts[0], default=0)
            src = parts[2] if len(parts) > 2 else "-"
            sport = self._safe_int(parts[3]) if len(parts) > 3 else 0
            dport = self._safe_int(parts[5]) if len(parts) > 5 else 0
            dst = parts[4] if len(parts) > 4 else "-"
            proto = parts[6].lower() if len(parts) > 6 and parts[6] != "-" else "-"
            service = parts[7].lower() if len(parts) > 7 else "-"
            duration = self._safe_float(parts[8]) if len(parts) > 8 else 0.0
            orig_bytes = self._safe_float(parts[9]) if len(parts) > 9 else 0.0
            resp_bytes = self._safe_float(parts[10]) if len(parts) > 10 else 0.0
            conn_state = parts[11] if len(parts) > 11 else ""
            orig_pkts = self._safe_float(parts[12]) if len(parts) > 12 else 0.0
            resp_pkts = self._safe_float(parts[13]) if len(parts) > 13 else 0.0
        except Exception:
            return None

        return {
            "ts": ts if ts else time.time(),
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "proto": proto,
            "service": service,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }

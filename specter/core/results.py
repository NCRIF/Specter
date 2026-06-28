"""
shared result models for scans and service hits
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SvcHit:
    port: int
    ok: bool
    state: str
    svc: str
    info: str
    elapsed: float
    n_cmd: str
    raw: str
    err: Optional[str] = None

    def to_dict(self):
        return {
            "port": self.port,
            "ok": self.ok,
            "state": self.state,
            "service": self.svc,
            "info": self.info,
            "elapsed_sec": self.elapsed,
            "nmap_cmd": self.n_cmd,
            "raw": self.raw,
            "err": self.err,
        }


@dataclass
class ScanHit:
    target: str
    ip: str
    req_ports: List[int]
    open_ports: List[int]
    svcs: List[SvcHit]
    started: str
    finished: str
    elapsed: float
    errors: List[str]

    def to_dict(self):
        return {
            "target": self.target,
            "ip": self.ip,
            "req_ports": self.req_ports,
            "open_ports": self.open_ports,
            "services": [s.to_dict() for s in self.svcs],
            "started": self.started,
            "finished": self.finished,
            "elapsed_sec": self.elapsed,
            "errors": self.errors,
        }


# compatibility aliases for older imports
SvcInfo = SvcHit
ScanOut = ScanHit

__all__ = ["SvcHit", "ScanHit", "SvcInfo", "ScanOut"]

# this code contains all the scan models for subdomain


from dataclasses import dataclass
from typing import List, Optional

from ...core.results import ScanHit, SvcHit


@dataclass
class ScanCfg:
    target: str
    ports: List[int]
    c_conc: int
    c_to: float
    s_conc: int
    n_args: List[str]
    svc_on: bool
    aggr_on: bool
    sudo_pw: Optional[str]
    stealth: bool
    syn_scan: bool
    verbose: int = 0
    quiet: bool = False
    max_retries: int = 1


Cfg = ScanCfg
SvcInfo = SvcHit
ScanOut = ScanHit


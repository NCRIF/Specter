# this code contains all the scan models for subdomain


from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class SubHit:
    subdomain: str
    ip: str
    sources: List[str]
    ports: List[int]
    status: int
    title: str
    server: str
    tech: List[str]
    elapsed: float
    err: Optional[str] = None

    def to_dict(self):
        return self.__dict__


@dataclass
class SubRun:
    domain: str
    subdomains: List[SubHit]
    total_found: int
    total_resolved: int
    started: str
    finished: str
    elapsed: float
    errors: List[str]

    def to_dict(self):
        data = dict(self.__dict__)
        data["subdomains"] = [sub.to_dict() for sub in self.subdomains]
        return data


@dataclass
class SubCfg:
    domain: str
    shodan_key: Optional[str]
    brute: bool
    wordlist: Optional[Path]
    nmap_on: bool
    scrape_on: bool
    resolve_c: int
    nmap_c: int
    http_to: float
    debug: bool
    verbose: int = 0
    quiet: bool = False


SubInfo = SubHit
SubScanOut = SubRun
Cfg = SubCfg


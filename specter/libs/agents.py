import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

AGENT_LABEL = "x3r0-agent"
DEFAULT_IMAGE = os.environ.get("X3R0_AGENT_IMAGE", "x3r0/warp-agent:v4")
DEFAULT_PREFIX = os.environ.get("X3R0_AGENT_PREFIX", "x3r0-agent")
SPECTER_PATH = os.environ.get("X3R0_SPECTER_PATH", os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
))
DOCKERFILE_DIR = os.environ.get("X3R0_AGENT_DOCKERFILE_DIR", SPECTER_PATH)

_agent_image_checked = False


def _docker(args, timeout=120):
    cmd = ["docker"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 1, "", "docker not found"
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"


def _image_exists(image=DEFAULT_IMAGE):
    code, _, _ = _docker(["image", "inspect", image], timeout=20)
    return code == 0


def setup_agent_image(image=DEFAULT_IMAGE):
    global _agent_image_checked
    if _agent_image_checked:
        return True
    if _image_exists(image):
        _agent_image_checked = True
        return True
    print(f"  building agent image {image} (one-time setup)")
    dockerfile_dir = DOCKERFILE_DIR
    code, _, err = _docker(["build", "-t", image, dockerfile_dir], timeout=300)
    if code != 0:
        print(f"  ERROR: docker build failed: {err[:200]}")
        return False
    _agent_image_checked = True
    return True


def _agent_names(prefix=DEFAULT_PREFIX):
    code, out, _ = _docker([
        "ps", "-a", "--filter", f"label={AGENT_LABEL}=true",
        "--format", "{{.Names}}"
    ])
    if code != 0:
        return []
    return [n for n in out.splitlines() if n.strip() and n.startswith(prefix)]


def agents_spawn(count, image=DEFAULT_IMAGE, prefix=DEFAULT_PREFIX):
    existing = _agent_names(prefix)
    have = len(existing)
    need = count - have
    if need <= 0:
        return existing[:count]

    for i in range(need):
        name = f"{prefix}-{have + i + 1}"
        _docker([
            "run", "-d", "--name", name,
            "--label", f"{AGENT_LABEL}=true",
            "--cap-add=NET_ADMIN",
            "--device=/dev/net/tun",
            "--restart=unless-stopped",
            image,
        ], timeout=30)
        time.sleep(1)

    time.sleep(10)
    return _agent_names(prefix)[:count]


def agent_scan(name, targets, ports_str, timeout, out_file, extra_args=None, retries=1,
               batch=20, batch_delay_ms=4.0):
    pid = _docker(["inspect", "-f", "{{.State.Pid}}", name], timeout=10)
    if pid[0] != 0 or not pid[1].strip():
        return 1, "", "no pid"
    container_pid = pid[1].strip()

    specter_bin = shutil.which("specter") or os.path.expanduser("~/.local/bin/specter")
    nsenter_cmd = [
        "nsenter", "-t", container_pid, "-n", "--",
        specter_bin, "scan",
    ] + targets + [
        "-p", ports_str,
        "-t", str(timeout),
        "-q", "--syn-scan", "-R", str(retries),
        "--batch", str(batch), "--batch-delay", str(batch_delay_ms),
    ]
    if extra_args:
        nsenter_cmd.extend(extra_args)
    nsenter_cmd.extend(["-o", out_file])

    try:
        sudo_pw = os.environ.get("SUDO_PASSWORD", "")
        if sudo_pw:
            r = subprocess.run(
                ["sudo", "-S"] + nsenter_cmd,
                input=sudo_pw + "\n",
                capture_output=True, text=True,
                timeout=int(timeout * len(targets)) + 60,
            )
            return r.returncode, r.stdout, r.stderr
        else:
            r = subprocess.run(
                ["sudo"] + nsenter_cmd,
                timeout=int(timeout * len(targets)) + 60,
            )
            return r.returncode, "", ""
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except FileNotFoundError:
        return 1, "", "nsenter not found"


def agents_kill(prefix=DEFAULT_PREFIX):
    names = _agent_names(prefix)
    for name in names:
        _docker(["rm", "-f", name], timeout=10)
    return len(names)

import logging
import sys
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).parent / "access.log"

logger = logging.getLogger("dpvl")
logger.setLevel(logging.DEBUG)

fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

fh = logging.FileHandler(LOG_FILE, mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(fmt)
logger.addHandler(fh)

sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
sh.setFormatter(fmt)
logger.addHandler(sh)


def log(method: str, path: str, status: int, detail: str = ""):
    msg = f"{method:6s} {status:3d}  {path}"
    if detail:
        msg += f"  |  {detail}"
    logger.info(msg)


def log_scenario_view(name: str, ip: str = ""):
    logger.info(f"VIEW    {name}  [{ip}]")


def log_action(action: str, params: str = ""):
    logger.info(f"ACTION  {action}  {params}".strip())

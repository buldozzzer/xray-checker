"""Web service that checks availability of remnawave subscription servers through xray-core."""
import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from checker import TARGETS, Node, XrayManager, fetch_subscription, probe
from history import History

BASE_DIR = Path(__file__).parent
SUB_URL = os.getenv("SUB_URL", "")
USER_AGENT = os.getenv("SUB_USER_AGENT", "Happ/5.6.0/ios/2608171408551")
XRAY_BIN = os.getenv("XRAY_BIN", str(BASE_DIR / "bin" / "xray"))
BASE_PORT = int(os.getenv("XRAY_BASE_PORT", "20000"))
TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "60"))
CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "24"))
AUTO_INTERVAL = int(os.getenv("AUTO_CHECK_INTERVAL", "0"))  # seconds, 0 = off
WATCH_INTERVAL = int(os.getenv("WATCH_CHECK_INTERVAL", str(12 * 3600)))  # seconds, 0 = off
DATA_DIR = BASE_DIR / "data"
STATE_FILE = DATA_DIR / "state.json"
HISTORY_DAYS = int(os.getenv("HISTORY_DAYS", "90"))  # 0 = keep forever

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


class State:
    def __init__(self):
        self.nodes: list[Node] = []
        self.results: dict[str, dict[int, dict]] = {k: {} for k in TARGETS}
        self.loaded_at: float | None = None
        self.load_error: str | None = None
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task] = set()
        DATA_DIR.mkdir(exist_ok=True)
        self.xray = XrayManager(XRAY_BIN, BASE_PORT, str(DATA_DIR))
        self.history = History(str(DATA_DIR / "history.db"), HISTORY_DAYS)
        # persisted across restarts; keyed by server name since node ids change on reload
        self.saved: dict[str, dict[str, dict]] = {k: {} for k in TARGETS}
        self.watched: set[str] = set()
        self.watch_last_run: float | None = None
        self._load()

    def _load(self):
        try:
            d = json.loads(STATE_FILE.read_text())
        except FileNotFoundError:
            return
        except Exception:
            log.exception("failed to read %s", STATE_FILE)
            return
        for k, v in d.get("results", {}).items():
            if k in self.saved:
                self.saved[k] = v
        self.watched = set(d.get("watched", []))
        self.watch_last_run = d.get("watch_last_run")

    def save(self):
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "results": self.saved,
            "watched": sorted(self.watched),
            "watch_last_run": self.watch_last_run,
        }, ensure_ascii=False))
        tmp.replace(STATE_FILE)


state = State()


async def reload_subscription():
    async with state.lock:
        for t in list(state.tasks):
            t.cancel()
        try:
            if not SUB_URL:
                raise RuntimeError("SUB_URL is not set")
            nodes = await fetch_subscription(SUB_URL, USER_AGENT)
            await state.xray.start(nodes)
        except Exception as e:
            log.exception("subscription load failed")
            state.load_error = f"{type(e).__name__}: {e}"
            raise
        state.nodes = nodes
        state.results = {k: {n.id: state.saved[k][n.name] for n in nodes if n.name in state.saved[k]} for k in TARGETS}
        state.loaded_at = time.time()
        state.load_error = None
        log.info("loaded %d nodes", len(nodes))


async def _check_one(node: Node, target: str, source: str):
    slot = state.results[target]
    slot[node.id] = {"state": "queued"}
    async with state.sem:
        slot[node.id] = {"state": "running", "started": time.time()}
        res = await probe(node, target, TIMEOUT)
    res.update(state="done", ts=time.time())
    if state.results.get(target) is slot:  # skip if subscription was reloaded meanwhile
        slot[node.id] = res
        state.saved[target][node.name] = res
        state.save()
        state.history.add(node.name, target, source, res)


def schedule(node_ids: list[int] | None, targets: list[str], source: str = "manual"):
    nodes = state.nodes if node_ids is None else [n for n in state.nodes if n.id in set(node_ids)]
    for target in targets:
        for n in nodes:
            if state.results[target].get(n.id, {}).get("state") in ("queued", "running"):
                continue
            t = asyncio.create_task(_check_one(n, target, source))
            state.tasks.add(t)
            t.add_done_callback(state.tasks.discard)
    return len(nodes) * len(targets)


async def auto_loop():
    while True:
        await asyncio.sleep(AUTO_INTERVAL)
        schedule(None, list(TARGETS), "auto")


async def watch_loop():
    """Checks watched servers on all targets every WATCH_INTERVAL; the schedule survives restarts."""
    while True:
        last = state.watch_last_run or 0
        await asyncio.sleep(max(0.0, last + WATCH_INTERVAL - time.time()))
        ids = [n.id for n in state.nodes if n.name in state.watched]
        if not ids:  # nothing watched yet or subscription not loaded
            await asyncio.sleep(60)
            continue
        log.info("background check of %d watched server(s)", len(ids))
        schedule(ids, list(TARGETS), "watch")
        state.history.prune()
        state.watch_last_run = time.time()
        state.save()


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        await reload_subscription()
    except Exception:
        pass  # surfaced in /api/state; user can retry from the UI
    bg = []
    if AUTO_INTERVAL > 0:
        bg.append(asyncio.create_task(auto_loop()))
    if WATCH_INTERVAL > 0:
        bg.append(asyncio.create_task(watch_loop()))
    yield
    for t in bg:
        t.cancel()
    await state.xray.stop()


app = FastAPI(title="xray-checker", lifespan=lifespan)


class CheckRequest(BaseModel):
    targets: list[str]
    ids: list[int] | None = None


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/state")
async def get_state():
    return {
        "nodes": [n.public() for n in state.nodes],
        "targets": TARGETS,
        "results": state.results,
        "loaded_at": state.loaded_at,
        "load_error": state.load_error,
        "timeout": TIMEOUT,
        "active": len(state.tasks),
        "watched": sorted(state.watched),
        "watch_interval": WATCH_INTERVAL,
        "watch_last_run": state.watch_last_run,
        "recent": state.history.recent_for([n.name for n in state.nodes]),
    }


@app.get("/api/history")
async def history(name: str, days: float = 30):
    return state.history.server(name, days)


@app.post("/api/check")
async def check(req: CheckRequest):
    bad = [t for t in req.targets if t not in TARGETS]
    if bad or not req.targets:
        raise HTTPException(400, f"unknown targets: {bad}")
    if not state.nodes:
        raise HTTPException(409, "subscription not loaded")
    return {"scheduled": schedule(req.ids, req.targets)}


class WatchRequest(BaseModel):
    name: str
    on: bool


@app.post("/api/watch")
async def watch(req: WatchRequest):
    if req.on:
        state.watched.add(req.name)
    else:
        state.watched.discard(req.name)
    state.save()
    return {"watched": sorted(state.watched)}


@app.post("/api/reload")
async def reload():
    try:
        await reload_subscription()
    except Exception as e:
        raise HTTPException(502, str(e))
    return {"nodes": len(state.nodes)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8080")))

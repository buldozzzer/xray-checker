"""Web service that checks availability of remnawave subscription servers through xray-core."""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from checker import TARGETS, Node, XrayManager, fetch_subscription, probe

BASE_DIR = Path(__file__).parent
SUB_URL = os.getenv("SUB_URL", "")
USER_AGENT = os.getenv("SUB_USER_AGENT", "Happ/5.6.0/ios/2608171408551")
XRAY_BIN = os.getenv("XRAY_BIN", str(BASE_DIR / "bin" / "xray"))
BASE_PORT = int(os.getenv("XRAY_BASE_PORT", "20000"))
TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "60"))
CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "24"))
AUTO_INTERVAL = int(os.getenv("AUTO_CHECK_INTERVAL", "0"))  # seconds, 0 = off

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
        workdir = BASE_DIR / "data"
        workdir.mkdir(exist_ok=True)
        self.xray = XrayManager(XRAY_BIN, BASE_PORT, str(workdir))


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
        state.results = {k: {} for k in TARGETS}
        state.loaded_at = time.time()
        state.load_error = None
        log.info("loaded %d nodes", len(nodes))


async def _check_one(node: Node, target: str):
    slot = state.results[target]
    slot[node.id] = {"state": "queued"}
    async with state.sem:
        slot[node.id] = {"state": "running", "started": time.time()}
        res = await probe(node, target, TIMEOUT)
    res.update(state="done", ts=time.time())
    if state.results.get(target) is slot:  # skip if subscription was reloaded meanwhile
        slot[node.id] = res


def schedule(node_ids: list[int] | None, targets: list[str]):
    nodes = state.nodes if node_ids is None else [n for n in state.nodes if n.id in set(node_ids)]
    for target in targets:
        for n in nodes:
            if state.results[target].get(n.id, {}).get("state") in ("queued", "running"):
                continue
            t = asyncio.create_task(_check_one(n, target))
            state.tasks.add(t)
            t.add_done_callback(state.tasks.discard)
    return len(nodes) * len(targets)


async def auto_loop():
    while True:
        await asyncio.sleep(AUTO_INTERVAL)
        schedule(None, list(TARGETS))


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        await reload_subscription()
    except Exception:
        pass  # surfaced in /api/state; user can retry from the UI
    bg = asyncio.create_task(auto_loop()) if AUTO_INTERVAL > 0 else None
    yield
    if bg:
        bg.cancel()
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
    }


@app.post("/api/check")
async def check(req: CheckRequest):
    bad = [t for t in req.targets if t not in TARGETS]
    if bad or not req.targets:
        raise HTTPException(400, f"unknown targets: {bad}")
    if not state.nodes:
        raise HTTPException(409, "subscription not loaded")
    return {"scheduled": schedule(req.ids, req.targets)}


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

"""Subscription parsing, xray process management and proxied HTTP probes."""
import asyncio
import copy
import json
import logging
import os
import re
import socket
import statistics
import tempfile
import time
from dataclasses import dataclass, field, asdict

import aiohttp

log = logging.getLogger("checker")

NON_PROXY_PROTOCOLS = {"freedom", "blackhole", "dns", "loopback"}

TARGETS = {
    "youtube": {
        "label": "YouTube",
        "url": "https://www.youtube.com/generate_204",
        "kind": "latency",
    },
    "ovh1mb": {
        "label": "OVH 1Mb",
        "url": "https://proof.ovh.net/files/1Mb.dat",
        "kind": "download",
    },
    "cloudflare": {
        "label": "Cloudflare 204",
        "url": "http://cp.cloudflare.com/generate_204",
        "kind": "latency",
    },
    "ping": {
        "label": "Ping",
        "url": "",  # direct to the server's address:port, not through xray
        "kind": "ping",
    },
    # "ipify": {
    #     "label": "ipify",
    #     "url": "https://api.ipify.org?format=text",
    #     "kind": "ip",
    # },
}


PING_COUNT = int(os.getenv("PING_COUNT", "4"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "3"))  # seconds per attempt
# TCP connect can't reach these: they listen on UDP only, so ICMP is used instead
UDP_PROTOCOLS = {"hysteria", "hysteria2", "tuic", "wireguard"}
UDP_NETWORKS = {"kcp", "mkcp", "quic"}


@dataclass
class Node:
    id: int
    name: str
    protocol: str
    network: str
    security: str
    address: str
    port: int
    outbound: dict = field(repr=False)
    port_local: int = 0
    error: str | None = None  # set when xray rejects this outbound

    def public(self) -> dict:
        d = asdict(self)
        d.pop("outbound")
        return d


def _server_endpoint(ob: dict) -> tuple[str, int]:
    s = ob.get("settings", {})
    for key in ("vnext", "servers"):
        if s.get(key):
            srv = s[key][0]
            return srv.get("address", ""), int(srv.get("port", 0))
    return s.get("address", ""), int(s.get("port", 0) or 0)


def parse_subscription(configs: list[dict]) -> list[Node]:
    nodes: list[Node] = []
    for cfg in configs:
        remarks = (cfg.get("remarks") or "unnamed").strip()
        proxies = [o for o in cfg.get("outbounds", []) if o.get("protocol") not in NON_PROXY_PROTOCOLS]
        for ob in proxies:
            ob = copy.deepcopy(ob)
            ss = ob.get("streamSettings", {})
            # chained outbounds would point to tags that don't exist in our merged config
            ob.pop("proxySettings", None)
            ss.get("sockopt", {}).pop("dialerProxy", None)
            name = remarks if len(proxies) == 1 else f"{remarks} [{ob.get('tag')}]"
            addr, port = _server_endpoint(ob)
            nodes.append(Node(
                id=len(nodes),
                name=name,
                protocol=ob.get("protocol", "?"),
                network=ss.get("network", "tcp"),
                security=ss.get("security", "none"),
                address=addr,
                port=port,
                outbound=ob,
            ))
    return nodes


async def fetch_subscription(url: str, user_agent: str) -> list[Node]:
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get(url, headers={"User-Agent": user_agent}) as r:
            r.raise_for_status()
            data = await r.json(content_type=None)
    if isinstance(data, dict):
        data = [data]
    return parse_subscription(data)


class XrayManager:
    """Runs a single xray process: one local HTTP inbound per node, routed to that node's outbound."""

    def __init__(self, binary: str, base_port: int, workdir: str):
        self.binary = binary
        self.base_port = base_port
        self.workdir = workdir
        self.proc: asyncio.subprocess.Process | None = None
        self.config_path = os.path.join(workdir, "xray-config.json")

    def _build(self, nodes: list[Node]) -> dict:
        inbounds, outbounds, rules = [], [], []
        for n in nodes:
            inbounds.append({
                "tag": f"in-{n.id}",
                "listen": "127.0.0.1",
                "port": n.port_local,
                "protocol": "http",
                "settings": {},
            })
            ob = copy.deepcopy(n.outbound)
            ob["tag"] = f"out-{n.id}"
            outbounds.append(ob)
            rules.append({"type": "field", "inboundTag": [f"in-{n.id}"], "outboundTag": f"out-{n.id}"})
        outbounds.append({"tag": "block", "protocol": "blackhole"})
        return {
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }

    async def _test(self, cfg: dict) -> str | None:
        fd, path = tempfile.mkstemp(suffix=".json", dir=self.workdir)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        try:
            p = await asyncio.create_subprocess_exec(
                self.binary, "run", "-test", "-c", path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await p.communicate()
            return None if p.returncode == 0 else out.decode(errors="replace").strip()[-500:]
        finally:
            os.unlink(path)

    async def start(self, nodes: list[Node]) -> None:
        await self.stop()
        for i, n in enumerate(nodes):
            n.port_local = self.base_port + i
            n.error = None
        valid = nodes
        if await self._test(self._build(nodes)):
            # find the offending outbounds one by one and drop them
            errs = await asyncio.gather(*(self._test(self._build([n])) for n in nodes))
            for n, e in zip(nodes, errs):
                n.error = e
            valid = [n for n in nodes if not n.error]
            log.warning("xray rejected %d outbound(s)", len(nodes) - len(valid))
        with open(self.config_path, "w") as f:
            json.dump(self._build(valid), f, ensure_ascii=False, indent=1)
        self.proc = await asyncio.create_subprocess_exec(
            self.binary, "run", "-c", self.config_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.sleep(1.0)
        if self.proc.returncode is not None:
            raise RuntimeError(f"xray exited with code {self.proc.returncode}")
        log.info("xray started (pid %s) with %d outbounds", self.proc.pid, len(valid))

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except asyncio.TimeoutError:
                self.proc.kill()
        self.proc = None


def _ping_result(rtts: list[float], sent: int, method: str) -> dict:
    res = {"method": method, "sent": sent, "recv": len(rtts), "loss": round(100 * (sent - len(rtts)) / sent, 1)}
    if not rtts:
        return {**res, "ok": False, "error": f"{method} timeout" if method == "icmp" else "no TCP connect"}
    return {**res, "ok": True, "ms": round(statistics.mean(rtts)), "min_ms": round(min(rtts)), "max_ms": round(max(rtts))}


async def _tcp_ping(host: str, port: int) -> dict:
    loop = asyncio.get_running_loop()
    try:  # resolve once so DNS time isn't counted as RTT
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), PING_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as e:
        return {"ok": False, "method": "tcp", "error": "DNS", "detail": str(e)[:300]}
    family, _, _, _, addr = infos[0]
    rtts, last_err = [], None
    for i in range(PING_COUNT):
        if i:
            await asyncio.sleep(0.2)
        t0 = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(addr[0], addr[1], family=family), PING_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as e:
            last_err = str(e) or type(e).__name__
            continue
        rtts.append((time.perf_counter() - t0) * 1000)
        w.close()
    res = _ping_result(rtts, PING_COUNT, "tcp")
    if not rtts and last_err:
        res["detail"] = last_err[:300]
    return res


async def _icmp_ping(host: str) -> dict:
    try:
        p = await asyncio.create_subprocess_exec(
            "ping", "-n", "-c", str(PING_COUNT), "-i", "0.2", "-W", str(max(1, round(PING_TIMEOUT))), host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        return {"ok": False, "method": "icmp", "error": "no ping binary"}
    out = (await p.communicate())[0].decode(errors="replace")
    rtts = [float(m) for m in re.findall(r"time[=<]([\d.]+) ?ms", out)]
    res = _ping_result(rtts, PING_COUNT, "icmp")
    if not rtts:
        res["detail"] = out.strip()[-300:]
    return res


async def ping(node: Node) -> dict:
    """RTT from this host straight to the server, bypassing xray."""
    if not node.address:
        return {"ok": False, "error": "no address"}
    if node.protocol in UDP_PROTOCOLS or node.network in UDP_NETWORKS or not node.port:
        return await _icmp_ping(node.address)
    return await _tcp_ping(node.address, node.port)


async def probe(node: Node, target_key: str, timeout_s: float) -> dict:
    """Request the target through the node's local proxy inbound and time it."""
    target = TARGETS[target_key]
    if target["kind"] == "ping":
        return await ping(node)
    if node.error:
        return {"ok": False, "error": "xray config rejected", "detail": node.error}
    proxy = f"http://127.0.0.1:{node.port_local}"
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    # fresh session/connector per probe so every measurement includes the full handshake
    t0 = time.perf_counter()
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(force_close=True)) as s:
            async with s.get(target["url"], proxy=proxy, allow_redirects=False,
                             headers={"User-Agent": "Mozilla/5.0 xray-checker"}) as r:
                ttfb = time.perf_counter() - t0
                body = await r.read()
                total = time.perf_counter() - t0
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"timeout {timeout_s:.0f}s"}
    except aiohttp.ClientError as e:
        return {"ok": False, "error": type(e).__name__, "detail": str(e)[:300]}

    res = {
        "ok": r.status < 400,
        "status": r.status,
        "ms": round(total * 1000),
        "ttfb_ms": round(ttfb * 1000),
        "bytes": len(body),
    }
    if not res["ok"]:
        res["error"] = f"HTTP {r.status}"
    if target["kind"] == "download" and total > 0:
        res["mbps"] = round(len(body) * 8 / total / 1e6, 2)
    if target["kind"] == "ip":
        res["ip"] = body.decode(errors="replace").strip()[:64]
    return res

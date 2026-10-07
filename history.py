"""Append-only log of every finished check, stored in SQLite."""
import sqlite3
import time
from collections import defaultdict, deque

RECENT = 30  # last checks per (server, target) kept in memory for the cards


class History:
    def __init__(self, path: str, retention_days: int):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS checks (
            ts REAL NOT NULL, name TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL,
            ok INTEGER NOT NULL, ms INTEGER, mbps REAL, error TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS checks_name_ts ON checks (name, ts)")
        self.retention_days = retention_days
        self.prune()
        self.recent: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=RECENT)))
        for ts, name, target, ok in self.db.execute(
                "SELECT ts, name, target, ok FROM checks ORDER BY ts"):
            self.recent[name][target].append([ts, ok])

    def add(self, name: str, target: str, source: str, res: dict):
        self.db.execute("INSERT INTO checks VALUES (?,?,?,?,?,?,?,?)", (
            res["ts"], name, target, source, int(res["ok"]), res.get("ms"), res.get("mbps"), res.get("error")))
        self.db.commit()
        self.recent[name][target].append([res["ts"], int(res["ok"])])

    def prune(self):
        if self.retention_days > 0:
            self.db.execute("DELETE FROM checks WHERE ts < ?", (time.time() - self.retention_days * 86400,))
            self.db.commit()

    def recent_for(self, names: list[str]) -> dict:
        """Compact form for the polled state: oldest-to-newest outcomes as a "1"/"0" string."""
        return {n: {t: "".join(str(ok) for _, ok in q) for t, q in self.recent[n].items()}
                for n in names if n in self.recent}

    def server(self, name: str, days: float) -> dict:
        since = time.time() - days * 86400
        rows = self.db.execute(
            "SELECT ts, target, source, ok, ms, mbps, error FROM checks WHERE name = ? AND ts >= ? ORDER BY ts DESC",
            (name, since)).fetchall()
        checks = [dict(zip(("ts", "target", "source", "ok", "ms", "mbps", "error"), r)) for r in rows]
        uptime = {}
        for label, d in (("24h", 1), ("7d", 7), ("30d", 30)):
            t0 = time.time() - d * 86400
            for target, total, ok in self.db.execute(
                    "SELECT target, COUNT(*), SUM(ok) FROM checks WHERE name = ? AND ts >= ? GROUP BY target",
                    (name, t0)):
                uptime.setdefault(target, {})[label] = {"total": total, "ok": ok}
        return {"name": name, "checks": checks, "uptime": uptime}

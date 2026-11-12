from __future__ import annotations

import ast

import pandas as pd

TIER_RANK = {"none": 0, "routine": 1, "low": 2, "sensitive": 3, "critical": 4}


class PathClassifier:
    """Turns the BETH `args` string into (path, tier, matched entry, is_write, in_writable_dir)."""

    def __init__(self, rules: dict):
        sp = rules["sensitive_paths"]
        self.routine = sp.get("routine", [])
        self.tiers = [(t, sp.get(t, [])) for t in ("critical", "sensitive", "low")]
        self.ww = tuple(rules["world_writable_dirs"])
        self.arg_names = set(rules["path_arg_names"])
        self.write_markers = tuple(rules["write_flag_markers"])
        self._cache: dict = {}

    @staticmethod
    def _match(path: str, entry: str) -> bool:
        return path.startswith(entry) if entry.startswith("/") else entry in path

    def classify(self, path: str):
        for e in self.routine:
            if self._match(path, e):
                return "routine", e
        for tier, entries in self.tiers:
            for e in entries:
                if self._match(path, e):
                    return tier, e
        return "none", ""

    def _write_flag(self, flags) -> bool:
        if isinstance(flags, str):
            return any(m in flags for m in self.write_markers)
        if isinstance(flags, int):
            return bool(flags & 0o3) or bool(flags & (0o100 | 0o1000 | 0o2000))
        return False

    def info(self, args_str: str):
        hit = self._cache.get(args_str)
        if hit is not None:
            return hit
        try:
            args = ast.literal_eval(args_str)
        except (ValueError, SyntaxError, MemoryError):
            args = []
        best = ("", "none", "")
        is_write = False
        if isinstance(args, list):
            for a in args:
                if not isinstance(a, dict):
                    continue
                name, val = a.get("name"), a.get("value")
                if name in self.arg_names and isinstance(val, str) and val:
                    tier, entry = self.classify(val)
                    if best[0] == "" or TIER_RANK[tier] > TIER_RANK[best[1]]:
                        best = (val, tier, entry)
                elif name in ("flags", "oflag"):
                    is_write = is_write or self._write_flag(val)
        in_ww = bool(best[0]) and best[0].startswith(self.ww)
        res = (best[0], best[1], best[2], is_write, in_ww)
        self._cache[args_str] = res
        return res


def add_event_features(df: pd.DataFrame, rules: dict) -> pd.DataFrame:
    """Add per-event features. Uses only behavioural columns, never sus/evil."""
    pc = PathClassifier(rules)
    cat_of = {n: c for c, names in rules["risky_syscalls"].items() for n in names}
    sev_of = rules["category_severity"]
    out = df.copy()
    out["failed"] = out["returnValue"] < 0
    out["is_root"] = out["userId"] == 0
    out["category"] = out["eventName"].map(cat_of).fillna("")
    out["severity"] = out["category"].map(sev_of).fillna("")

    wanted = set(rules["path_events"]) | set(cat_of)
    mask = out["eventName"].isin(wanted).to_numpy()
    n = len(out)
    path, tier, entry = [""] * n, ["none"] * n, [""] * n
    wr, ww = [False] * n, [False] * n
    for i, (a, m) in enumerate(zip(out["args"].to_numpy(), mask)):
        if m and a != "[]":
            path[i], tier[i], entry[i], wr[i], ww[i] = pc.info(a)
    out["path"], out["path_tier"], out["path_entry"] = path, tier, entry
    out["is_write"], out["in_wwdir"] = wr, ww
    return out

from __future__ import annotations

import json
import math
import pathlib

import numpy as np
import pandas as pd


def _clean(o):
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        return None if (math.isnan(o) or math.isinf(o)) else float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    return o


GROUP_FIELDS = ["group_id", "hostName", "processId", "processName", "parentProcessId", "first_ts",
                "last_ts", "n_events", "behavior", "privilege", "resource", "supporting", "score",
                "tier", "indicators", "reasons", "evidence", "sus_any", "evil_any", "disagreement"]


def export_dashboard(groups: pd.DataFrame, results: dict, meta: dict, out_dir,
                     max_groups: int = 3000) -> None:
    """Write dashboard/results.js (loads via file://) and results.json."""
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    bins = [0] * 10
    for s in groups["score"]:
        bins[min(int(s) // 10, 9)] += 1
    summary = {"total_groups": int(len(groups)),
               "tiers": {k: int(v) for k, v in groups["tier"].value_counts().items()},
               "histogram": bins}

    keep = groups[(groups["tier"] != "low") | (groups["disagreement"] != "")]
    room = max(0, max_groups - len(keep))
    rest = groups.drop(keep.index).sort_values("score", ascending=False).head(room)
    sel = pd.concat([keep, rest]).sort_values("score", ascending=False).head(max_groups)

    payload = {"meta": meta, "summary": summary, "metrics": results,
               "groups": sel[GROUP_FIELDS].to_dict("records")}
    payload = _clean(payload)
    text = json.dumps(payload, separators=(",", ":"))
    (out / "results.json").write_text(text, encoding="utf-8")
    (out / "results.js").write_text("window.RESULTS = " + text + ";\n", encoding="utf-8")

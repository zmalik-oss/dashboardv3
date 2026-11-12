from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import pandas as pd


@dataclass
class Baseline:
    """What 'normal' looks like, learned from the training split without using labels."""

    n_events: int
    process_counts: dict
    root_fraction: dict
    pair_counts: dict   # "process|eventName" -> count
    path_counts: dict   # "process|matched path entry" -> count

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f)

    @classmethod
    def load(cls, path) -> "Baseline":
        with open(path, "r", encoding="utf-8") as f:
            return cls(**json.load(f))


def fit_baseline(df_feat: pd.DataFrame) -> Baseline:
    proc = df_feat["processName"]
    pcounts = {k: int(v) for k, v in proc.value_counts().items()}
    root = {k: float(v) for k, v in df_feat["is_root"].groupby(proc).mean().items()}
    pair = (proc + "|" + df_feat["eventName"]).value_counts()
    pathdf = df_feat[df_feat["path_entry"] != ""]
    ptc = (pathdf["processName"] + "|" + pathdf["path_entry"]).value_counts()
    return Baseline(
        n_events=int(len(df_feat)),
        process_counts=pcounts,
        root_fraction=root,
        pair_counts={k: int(v) for k, v in pair.items()},
        path_counts={k: int(v) for k, v in ptc.items()},
    )

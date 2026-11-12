from __future__ import annotations

import pandas as pd


def assign_groups(df: pd.DataFrame, gap_seconds: float) -> pd.DataFrame:
    """Collapse related events into one 'action group'.

    Events belong to the same group when they share a host and processId and each is
    within `gap_seconds` of the previous one. This implements the rubric's rule that
    several system calls from one action must not count as separate threats, and it
    gives the Supporting Evidence factor its context (events before and after).
    """
    out = df.sort_values(["hostName", "processId", "timestamp", "row_id"]).reset_index(drop=True)
    new_proc = (out["hostName"] != out["hostName"].shift()) | (out["processId"] != out["processId"].shift())
    big_gap = out["timestamp"].diff() > gap_seconds
    out["group_id"] = (new_proc | big_gap).cumsum() - 1
    return out

from __future__ import annotations

import pandas as pd

REQUIRED = [
    "timestamp", "processId", "parentProcessId", "userId", "processName",
    "hostName", "eventName", "returnValue", "args",
]


def prepare_frame(df: pd.DataFrame, source: str = "frame") -> pd.DataFrame:
    """Validate and normalize a BETH-shaped frame (shared by load_beth and the tests)."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"{source}: missing expected BETH columns: {missing}")
    df = df.copy()
    for lab in ("sus", "evil"):
        if lab not in df.columns:
            df[lab] = 0
        df[lab] = pd.to_numeric(df[lab], errors="coerce").fillna(0).astype(int)
    df["args"] = df["args"].fillna("[]").astype(str)
    df["processName"] = df["processName"].astype(str)
    df["hostName"] = df["hostName"].astype(str)
    df["eventName"] = df["eventName"].astype(str)
    df["row_id"] = range(len(df))
    return df.sort_values(["hostName", "processId", "timestamp", "row_id"]).reset_index(drop=True)


def load_beth(path, nrows=None) -> pd.DataFrame:
    """Load a BETH split (labelled_train/validation/test.csv).

    The sus/evil labels are kept in the frame ONLY so the benchmark can use them as an
    answer key. Nothing in features.py, baseline.py or scoring.py reads them.
    """
    return prepare_frame(pd.read_csv(path, nrows=nrows), source=str(path))


def describe(df: pd.DataFrame, top: int = 25) -> str:
    """Text summary used to adapt rules.yaml to the real data."""
    lines = [f"rows: {len(df):,}", f"hosts: {df['hostName'].nunique()}",
             f"processes (pid): {df['processId'].nunique():,}",
             f"sus=1: {int((df['sus'] > 0).sum()):,}   evil=1: {int((df['evil'] > 0).sum()):,}",
             f"userId==0 share: {(df['userId'] == 0).mean():.1%}",
             f"returnValue<0 share: {(df['returnValue'] < 0).mean():.1%}", "",
             f"top {top} eventName values:"]
    for k, v in df["eventName"].value_counts().head(top).items():
        lines.append(f"  {k:<32}{v:>10,}")
    lines += ["", f"top {top} processName values:"]
    for k, v in df["processName"].value_counts().head(top).items():
        lines.append(f"  {k:<32}{v:>10,}")
    return "\n".join(lines)

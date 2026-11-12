from __future__ import annotations

import numpy as np
import pandas as pd

from .baseline import Baseline
from .grouping import assign_groups

FACTOR_MAX = {"behavior": 40, "privilege": 20, "resource": 20, "supporting": 20}
IOC_COLS = ["ioc_exec_tmp", "ioc_log_tamper", "ioc_cred_modify", "ioc_module_load"]
EVIDENCE_COLS = ["hi_fail", "hi_succ", "med_fail", "sens_nr", "crit_mod_succ",
                 "priv_succ_nr", "priv_fail_nr"] + IOC_COLS

INDICATOR_TEXT = {
    "failed_attempt": "failed risky or sensitive attempt",
    "unexpected_success": "successful non-routine risky action",
    "unexpected_sensitive_access": "unexpected access to a sensitive file",
    "privilege_anomaly": "unusual privilege use",
    "privilege_escalation": "unexpected escalation to root",
    "exec_from_writable_dir": "executed a file from a world-writable directory",
    "log_tampering": "modified or deleted log files",
    "credential_file_modified": "modified a credential or SSH config file",
    "kernel_module_loaded": "loaded a kernel module",
    "network_failure_burst": "very large burst of failed network calls",
    "rare_process": "process rarely or never seen in baseline",
}


def tier_for(score, medium_min=40, high_min=70):
    """Rubric tiers: <40 low, 40-69 medium, >=70 high."""
    return "high" if score >= high_min else ("medium" if score >= medium_min else "low")


def _event_flags(df: pd.DataFrame, bl: Baseline, rules: dict) -> pd.DataFrame:
    rmin = rules["baseline"]["routine_min_count"]
    ioc = rules["ioc"]
    pair = (df["processName"] + "|" + df["eventName"]).map(bl.pair_counts).fillna(0)
    pcount = (df["processName"] + "|" + df["path_entry"]).map(bl.path_counts).fillna(0)
    routine_pair = pair >= rmin
    path_expected = (df["path_entry"] != "") & (pcount >= rmin)
    sens = df["path_tier"].isin(["critical", "sensitive"])
    sens_nr = sens & ~path_expected
    hi_nr = (df["severity"] == "high") & ~routine_pair
    med_nr = (df["severity"] == "medium") & ~routine_pair
    failed = df["failed"]
    crit = df["path_tier"] == "critical"
    modified = df["is_write"] | (df["category"] == "file_modification")
    entry = df["path_entry"]

    f = pd.DataFrame(index=df.index)
    f["hi_fail"] = hi_nr & failed
    f["hi_succ"] = hi_nr & ~failed
    f["med_fail"] = med_nr & failed
    f["med_nr"] = med_nr
    f["sens_nr"] = sens_nr
    f["sens_nr_fail"] = sens_nr & failed
    f["sens_exp"] = sens & path_expected
    f["crit_mod_succ"] = crit & modified & ~failed & ~path_expected
    f["low_path"] = df["path_tier"] == "low"
    f["priv_succ_nr"] = (df["category"] == "privilege_change") & ~failed & ~routine_pair
    f["priv_fail_nr"] = (df["category"] == "privilege_change") & failed & ~routine_pair
    f["risky_any"] = df["category"] != ""
    f["ioc_exec_tmp"] = (df["category"] == "execution") & ~failed & df["in_wwdir"] & ~path_expected
    f["ioc_log_tamper"] = f["crit_mod_succ"] & entry.isin(ioc["log_entries"])
    f["ioc_cred_modify"] = f["crit_mod_succ"] & entry.isin(ioc["credential_entries"])
    f["ioc_module_load"] = df["eventName"].isin(ioc["module_events"]) & ~failed & ~routine_pair
    f["failed_nr"] = f["hi_fail"] | f["med_fail"] | f["sens_nr_fail"]
    f["net_fail_nr"] = f["med_fail"] & (df["category"] == "network")
    return f


def score_events(df_feat: pd.DataFrame, bl: Baseline, rules: dict):
    """Score every action group. Returns (groups, events).

    groups: one row per action group with the four rubric factors, total score, tier,
            indicators, human-readable reasons, and (for benchmarking only) the dataset labels.
    events: every event with its group's score/tier, for event-level benchmarking.
    """
    b = rules["baseline"]
    tiers = rules["tiers"]
    repeat = rules["repeat_threshold"]

    df = assign_groups(df_feat, rules["grouping"]["gap_seconds"])
    f = _event_flags(df, bl, rules)
    tmp = pd.concat([df[["group_id"]], f], axis=1)
    G = tmp.groupby("group_id")[[c for c in f.columns if c not in ("failed_nr", "net_fail_nr")]].any()
    failed_count = tmp.groupby("group_id")["failed_nr"].sum()
    net_fail_count = tmp.groupby("group_id")["net_fail_nr"].sum()

    meta = df.groupby("group_id").agg(
        hostName=("hostName", "first"), processId=("processId", "first"),
        processName=("processName", "first"), parentProcessId=("parentProcessId", "first"),
        first_ts=("timestamp", "min"), last_ts=("timestamp", "max"),
        n_events=("eventName", "size"), first_uid=("userId", "first"),
        any_root=("is_root", "max"), sus_any=("sus", "max"),
        evil_any=("evil", "max"), evil_frac=("evil", "mean"),
    )

    base_root = meta["processName"].map(bl.root_fraction)
    proc_count = meta["processName"].map(bl.process_counts).fillna(0)
    rare = proc_count < b["rare_process_max_count"]
    root_low = b["root_low_fraction"]
    root_here = meta["any_root"].astype(bool)
    rep = failed_count >= repeat

    escalation = (meta["first_uid"] != 0) & root_here
    esc_unexp = escalation & (base_root.isna() | (base_root < root_low) | G["priv_succ_nr"])
    ioc_priv = esc_unexp & G["priv_succ_nr"]
    # Optional extension, OFF by default (ioc.network_burst_min_failures: null). It is not part of the
    # team's written rubric, so enabling it must be a team decision. See docs/rubric-to-rules.md.
    burst_min = rules["ioc"].get("network_burst_min_failures")
    burst = (net_fail_count >= burst_min) if burst_min else pd.Series(False, index=G.index)
    n_ioc = G[IOC_COLS].sum(axis=1) + ioc_priv.astype(int) + burst.astype(int)
    priv_any = G["priv_succ_nr"] | G["priv_fail_nr"] | esc_unexp

    behavior = np.select(
        [n_ioc >= 1, G["hi_succ"], G["hi_fail"] | (G["med_fail"] & rep), G["med_nr"] | G["sens_nr"]],
        [40, 30, 20, 10], default=0)
    privilege = np.select(
        [esc_unexp & (n_ioc >= 1), priv_any,
         root_here & base_root.notna() & (base_root < root_low), root_here & base_root.isna()],
        [20, 15, 10, 5], default=0)
    resource = np.select(
        [G["crit_mod_succ"], G["sens_nr"], G["sens_exp"], G["low_path"]],
        [20, 15, 10, 5], default=0)

    ind = pd.DataFrame({
        "failed_attempt": G["hi_fail"] | G["med_fail"] | G["sens_nr_fail"],
        "unexpected_success": G["hi_succ"],
        "unexpected_sensitive_access": G["sens_nr"],
        "privilege_anomaly": priv_any & ~ioc_priv,
        "privilege_escalation": ioc_priv,
        "exec_from_writable_dir": G["ioc_exec_tmp"],
        "log_tampering": G["ioc_log_tamper"],
        "credential_file_modified": G["ioc_cred_modify"],
        "kernel_module_loaded": G["ioc_module_load"],
        "network_failure_burst": burst,
        "rare_process": rare & (G["risky_any"] | G["sens_nr"]),
    })
    n_ind = ind.sum(axis=1)
    supporting = np.select(
        [n_ioc >= 2, n_ind >= 4, (n_ind == 3) | rep, n_ind == 2],
        [20, 15, 10, 5], default=0)

    groups = meta.copy()
    groups["behavior"], groups["privilege"] = behavior, privilege
    groups["resource"], groups["supporting"] = resource, supporting
    groups["score"] = groups[["behavior", "privilege", "resource", "supporting"]].sum(axis=1)
    groups["tier"] = np.select(
        [groups["score"] >= tiers["high_min"], groups["score"] >= tiers["medium_min"]],
        ["high", "medium"], default="low")
    groups["indicators"] = [[c for c in ind.columns if row[c]] for _, row in ind.iterrows()]
    groups["n_ioc"] = n_ioc.astype(int)
    groups["escalation"] = esc_unexp
    groups["base_root"] = base_root
    groups["repeated"] = rep

    # Evidence events (what the analyst should look at first)
    flagged = df[f[EVIDENCE_COLS].any(axis=1)]
    ev: dict = {}
    for r in flagged.itertuples():
        lst = ev.setdefault(r.group_id, [])
        txt = f"{r.eventName}({r.returnValue})" + (f" {r.path}" if r.path else "")
        if txt not in lst and len(lst) < 5:
            lst.append(txt)
    groups["evidence"] = [ev.get(g, []) for g in groups.index]
    groups["reasons"] = [_reasons(r) for r in groups.itertuples()]

    groups["disagreement"] = np.select(
        [(groups["evil_any"] > 0) & (groups["tier"] == "low"),
         (groups["evil_any"] == 0) & (groups["tier"] == "high")],
        ["malicious_label_scored_low", "benign_label_scored_high"], default="")

    groups = groups.reset_index()
    events = df[["group_id", "row_id", "processName", "eventName", "sus", "evil"]].merge(
        groups[["group_id", "score", "tier"]], on="group_id", how="left")
    return groups, events


def _reasons(r) -> dict:
    ind = list(r.indicators)
    names = [INDICATOR_TEXT[i] for i in ind]
    beh = {40: "High-risk indicator: " + "; ".join(
               n for i, n in zip(ind, names) if i in
               ("exec_from_writable_dir", "log_tampering", "credential_file_modified",
                "kernel_module_loaded", "network_failure_burst", "privilege_escalation")),
           30: "Successful risky action that is not routine for this process",
           20: "Attempted risky or sensitive action that failed or repeated",
           10: "Unusual activity not seen in the baseline",
           0: "Normal activity for this process"}[r.behavior]
    prv = {20: "Unexpected privilege escalation alongside other high-risk indicators",
           15: "Privilege-changing call or escalation that is not routine for this process",
           10: "Root use by a process that normally runs unprivileged",
           5: "Root use by a process with no baseline",
           0: "Privilege use consistent with baseline"}[r.privilege]
    res = {20: "Critical file modified successfully and not routine for this process; review whether it was authorized",
           15: "Unexpected access (or failed attempt) on a sensitive or critical file",
           10: "Sensitive file accessed, but consistent with baseline",
           5: "Low-sensitivity location touched (for example /tmp)",
           0: "No sensitive resources touched"}[r.resource]
    sup = {20: "Multiple independent high-risk indicators in the same action",
           15: "Four or more distinct indicators in the same action",
           10: "Repeated attempts or three distinct indicators",
           5: "One additional indicator beyond the primary one",
           0: "No supporting evidence"}[r.supporting]
    return {"behavior": beh, "privilege": prv, "resource": res, "supporting": sup}

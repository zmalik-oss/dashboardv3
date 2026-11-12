from __future__ import annotations

import numpy as np
import pandas as pd


def metrics(y_true, y_pred) -> dict:
    yt = np.asarray(y_true).astype(bool)
    yp = np.asarray(y_pred).astype(bool)
    tp = int((yt & yp).sum())
    fp = int((~yt & yp).sum())
    fn = int((yt & ~yp).sum())
    tn = int((~yt & ~yp).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "alerts": tp + fp, "positives": tp + fn}


def workload(groups: pd.DataFrame, events: pd.DataFrame) -> dict:
    """How much analyst work the tiers remove (the rubric's stated goal)."""
    n = len(groups)
    c = groups["tier"].value_counts().to_dict()
    low, med, high = c.get("low", 0), c.get("medium", 0), c.get("high", 0)
    ev_low = int((events["tier"] == "low").sum())
    return {
        "groups": n, "low": low, "medium": med, "high": high,
        "pct_auto_logged": round(low / n, 4) if n else 0.0,
        "groups_needing_review": med + high,
        "events": len(events), "events_auto_logged": ev_low,
        "review_reduction_vs_all_groups": round(1 - (med + high) / n, 4) if n else 0.0,
    }


def framework_metrics(groups: pd.DataFrame, events: pd.DataFrame, rules: dict) -> dict:
    t = rules["tiers"]
    out = {}
    for name, thr in (("medium_plus", t["medium_min"]), ("high_only", t["high_min"])):
        out[f"group_{name}"] = metrics(groups["evil_any"] > 0, groups["score"] >= thr)
        out[f"event_{name}"] = metrics(events["evil"] > 0, events["score"] >= thr)
    out["workload"] = workload(groups, events)
    out["disagreements"] = {
        "malicious_label_scored_low": int((groups["disagreement"] == "malicious_label_scored_low").sum()),
        "benign_label_scored_high": int((groups["disagreement"] == "benign_label_scored_high").sum()),
    }
    return out


def false_alarm_rates(groups: pd.DataFrame, events: pd.DataFrame, rules: dict) -> dict:
    """On a split with no attacks (BETH validation), every Medium/High alert is a false alarm."""
    t = rules["tiers"]
    return {
        "groups": len(groups),
        "group_alert_rate_medium_plus": round(float((groups["score"] >= t["medium_min"]).mean()), 5),
        "group_alert_rate_high": round(float((groups["score"] >= t["high_min"]).mean()), 5),
        "event_alert_rate_medium_plus": round(float((events["score"] >= t["medium_min"]).mean()), 5),
        "event_alert_rate_high": round(float((events["score"] >= t["high_min"]).mean()), 5),
    }


def threshold_sweep(groups: pd.DataFrame, step: int = 5) -> list:
    rows = []
    for thr in range(0, 101, step):
        m = metrics(groups["evil_any"] > 0, groups["score"] >= thr)
        rows.append({"threshold": thr, "alert_rate": round(float((groups["score"] >= thr).mean()), 5),
                     "precision": m["precision"], "recall": m["recall"], "f1": m["f1"]})
    return rows


def sus_label_baseline(events: pd.DataFrame) -> dict:
    """Naive baseline: treat the dataset's own sus flag as the alert."""
    return metrics(events["evil"] > 0, events["sus"] > 0)


def _iforest_matrix(df: pd.DataFrame, enc: dict) -> np.ndarray:
    return np.column_stack([
        df["userId"].to_numpy(dtype=float),
        df["argsNum"].to_numpy(dtype=float) if "argsNum" in df.columns else np.zeros(len(df)),
        df["returnValue"].to_numpy(dtype=float),
        df["is_root"].to_numpy(dtype=float),
        df["failed"].to_numpy(dtype=float),
        df["processName"].map(enc["proc"]).fillna(0).to_numpy(dtype=float),
        df["eventName"].map(enc["event"]).fillna(0).to_numpy(dtype=float),
    ])


def isolation_forest_baseline(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame,
                              target_alert_rate: float, seed: int = 0) -> dict:
    """Unsupervised baseline on single events.

    Fit on train; the alert threshold is set so the alert rate on the (attack-free)
    validation split matches `target_alert_rate`, i.e. the same false-alarm budget the
    rule framework spends. Evaluated against evil on test.
    """
    from sklearn.ensemble import IsolationForest

    enc = {"proc": (train["processName"].value_counts(normalize=True)).to_dict(),
           "event": (train["eventName"].value_counts(normalize=True)).to_dict()}
    model = IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1)
    model.fit(_iforest_matrix(train, enc))
    val_s = -model.score_samples(_iforest_matrix(val, enc))
    test_s = -model.score_samples(_iforest_matrix(test, enc))
    rate = min(max(target_alert_rate, 0.001), 0.5)
    thr = float(np.quantile(val_s, 1 - rate))
    out = metrics(test["evil"] > 0, test_s >= thr)
    out["alert_rate_budget"] = round(rate, 5)
    return out


def write_report(path, split_names: dict, results: dict, is_sample: bool) -> None:
    fm = results["framework_test"]
    w = fm["workload"]
    lines = ["# Benchmark report", ""]
    if is_sample:
        lines += ["> **These numbers come from the synthetic sample data in `data/sample/`. "
                  "They test that the pipeline runs; they are not BETH results and must not be "
                  "reported as such.**", ""]
    lines += [f"Splits: train=`{split_names['train']}`, validation=`{split_names['val']}`, "
              f"test=`{split_names['test']}`.", "",
              "## Test split: detection vs. the `evil` label", "",
              "| Method | Level | Precision | Recall | F1 | Alerts | TP | FP | FN |",
              "|---|---|---|---|---|---|---|---|---|"]

    def row(name, level, m):
        return (f"| {name} | {level} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
                f"{m['alerts']} | {m['tp']} | {m['fp']} | {m['fn']} |")

    lines += [row("Rubric score >= 40 (Medium+)", "action group", fm["group_medium_plus"]),
              row("Rubric score >= 70 (High)", "action group", fm["group_high_only"]),
              row("Rubric score >= 40 (Medium+)", "event", fm["event_medium_plus"]),
              row("Rubric score >= 70 (High)", "event", fm["event_high_only"]),
              row("Baseline: `sus` flag", "event", results["baseline_sus"]),
              row("Baseline: Isolation Forest (matched alert budget)", "event", results["baseline_iforest"]),
              "", "## Analyst workload (test split)", "",
              f"- Action groups: {w['groups']:,} ({w['events']:,} events)",
              f"- Auto-logged (Low): {w['low']:,} ({w['pct_auto_logged']:.1%})",
              f"- Flagged (Medium): {w['medium']:,}   High-priority: {w['high']:,}",
              f"- Groups needing human review: {w['groups_needing_review']:,} "
              f"({1 - w['review_reduction_vs_all_groups']:.1%} of all groups)", "",
              "## False-alarm check (validation split, no attacks)", ""]
    fa = results["false_alarms_validation"]
    lines += [f"- Groups: {fa['groups']:,}",
              f"- Medium+ alert rate: {fa['group_alert_rate_medium_plus']:.3%} of groups, "
              f"{fa['event_alert_rate_medium_plus']:.3%} of events",
              f"- High alert rate: {fa['group_alert_rate_high']:.3%} of groups", "",
              "## Disagreements with the dataset labels (test)", "",
              f"- Labeled malicious but scored Low: {fm['disagreements']['malicious_label_scored_low']}",
              f"- Labeled benign but scored High: {fm['disagreements']['benign_label_scored_high']}",
              "", "These go to `review_queue.csv` for manual analysis. Each is either a scoring miss "
              "or a label that deserves a second look; the report should discuss specific cases.", "",
              "## Threshold sweep (test, informational only; thresholds stay at 40/70)", "",
              "| Threshold | Alert rate | Precision | Recall | F1 |", "|---|---|---|---|---|"]
    for r in results["sweep_test"]:
        lines.append(f"| {r['threshold']} | {r['alert_rate']:.3%} | {r['precision']:.3f} | "
                     f"{r['recall']:.3f} | {r['f1']:.3f} |")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

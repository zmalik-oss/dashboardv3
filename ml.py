"""Machine-learning models that score the same action groups the rubric scores.

Everything here is unsupervised: models are fit on the attack-free training split and never see
the sus/evil labels. Labels are used only afterwards, to grade the result.

Two model families are compared with the rubric at the SAME unit (the action group):

  A. "features" models: Isolation Forest and Local Outlier Factor on behaviour features of each
     group (volume, failure rate, risky-call mix, sensitive paths, rarity vs. the baseline).
  B. "hybrid" model: the same Isolation Forest, with the rubric's four factor scores and indicator
     count added as extra features, so the rubric's evidence feeds the model.

Process *names* are deliberately not features, so a model cannot simply learn "tsm is bad".
The baseline-dependent features for the training split are computed out-of-fold by host
(each training host is described using a baseline fit on the other hosts), so the training
groups do not look artificially "routine" compared with validation and test.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .baseline import fit_baseline
from .benchmark import metrics
from .grouping import assign_groups
from .scoring import score_events

CATS = ["privilege_change", "process_control", "system_modification",
        "file_modification", "execution", "network"]
COUNT_FEATURES = ["n_events", "n_failed", "n_net_failed", "n_sensitive", "n_critical", "n_wwdir",
                  "n_write", "n_distinct_events", "n_distinct_paths"] + ["n_" + c for c in CATS]
FRAC_FEATURES = ["fail_frac", "root_frac", "rare_pair_frac", "mean_log_pair"]
OTHER_FEATURES = ["log_duration", "log_rate", "log_proc_count"]
FEATURES = COUNT_FEATURES + FRAC_FEATURES + OTHER_FEATURES
RUBRIC_FEATURES = ["behavior", "privilege", "resource", "supporting", "score", "n_ioc"]
FEATURES_HYBRID = FEATURES + RUBRIC_FEATURES


def group_table(df_feat: pd.DataFrame, bl, rules: dict, groups: pd.DataFrame) -> pd.DataFrame:
    """One row per action group: behaviour features + rubric scores. No labels are read."""
    rmin = rules["baseline"]["routine_min_count"]
    df = assign_groups(df_feat, rules["grouping"]["gap_seconds"])
    pair = (df["processName"] + "|" + df["eventName"]).map(bl.pair_counts).fillna(0)
    x = pd.DataFrame({
        "group_id": df["group_id"],
        "one": 1,
        "failed": df["failed"].astype(int),
        "root": df["is_root"].astype(int),
        "rare_pair": (pair < rmin).astype(int),
        "log_pair": np.log1p(pair),
        "sens": df["path_tier"].isin(["critical", "sensitive"]).astype(int),
        "crit": (df["path_tier"] == "critical").astype(int),
        "wwdir": df["in_wwdir"].astype(int),
        "write": df["is_write"].astype(int),
        "net_failed": ((df["category"] == "network") & df["failed"]).astype(int),
    })
    for c in CATS:
        x["c_" + c] = (df["category"] == c).astype(int)
    agg = x.groupby("group_id").agg(
        n_events=("one", "sum"), n_failed=("failed", "sum"), n_net_failed=("net_failed", "sum"),
        n_sensitive=("sens", "sum"), n_critical=("crit", "sum"), n_wwdir=("wwdir", "sum"),
        n_write=("write", "sum"), root_frac=("root", "mean"), rare_pair_frac=("rare_pair", "mean"),
        mean_log_pair=("log_pair", "mean"), **{"n_" + c: ("c_" + c, "sum") for c in CATS})
    g = df.groupby("group_id")
    agg["n_distinct_events"] = g["eventName"].nunique()
    agg["n_distinct_paths"] = g["path"].nunique()
    agg["fail_frac"] = agg["n_failed"] / agg["n_events"]
    dur = g["timestamp"].max() - g["timestamp"].min()
    agg["log_duration"] = np.log1p(dur)
    agg["log_rate"] = np.log1p(agg["n_events"] / (dur + 1.0))
    proc = g["processName"].first()
    agg["log_proc_count"] = np.log1p(proc.map(bl.process_counts).fillna(0))

    t = groups.set_index("group_id")[RUBRIC_FEATURES[:-1] + ["n_ioc", "evil_any"]]
    t = t.loc[:, ~t.columns.duplicated()]
    out = agg.join(t[RUBRIC_FEATURES + ["evil_any"]], how="left")
    return out


def _transform(t: pd.DataFrame, cols: list) -> np.ndarray:
    m = t[cols].astype(float).copy()
    for c in COUNT_FEATURES:
        if c in m:
            m[c] = np.log1p(m[c])
    return m.to_numpy()


def train_table_out_of_fold(train: pd.DataFrame, rules: dict) -> pd.DataFrame:
    """Describe each training host with a baseline fit on the OTHER hosts."""
    hosts = sorted(train["hostName"].unique())
    parts = []
    for h in hosts:
        rest, mine = train[train["hostName"] != h], train[train["hostName"] == h]
        if rest.empty:                      # single-host training data: no out-of-fold possible
            rest = mine
        bl = fit_baseline(rest)
        g, _ = score_events(mine, bl, rules)
        t = group_table(mine, bl, rules, g)
        t["_host"] = h
        t.index = [f"{h}:{i}" for i in t.index]
        parts.append(t)
    return pd.concat(parts)


def _fit_scorers(Xtr, Xtr_h, seed):
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler

    rng = np.random.RandomState(seed)
    iso = IsolationForest(n_estimators=300, random_state=seed, n_jobs=-1).fit(Xtr)
    iso_h = IsolationForest(n_estimators=300, random_state=seed, n_jobs=-1).fit(Xtr_h)
    sc = StandardScaler().fit(Xtr)
    sub = Xtr if len(Xtr) <= 20000 else Xtr[rng.choice(len(Xtr), 20000, replace=False)]
    lof = LocalOutlierFactor(n_neighbors=35, novelty=True, n_jobs=-1).fit(sc.transform(sub))
    return {
        "isolation_forest_features": lambda X, Xh: -iso.score_samples(X),
        "local_outlier_factor_features": lambda X, Xh: -lof.score_samples(sc.transform(X)),
        "hybrid_isolation_forest_rubric_features": lambda X, Xh: -iso_h.score_samples(Xh),
    }


def _auc(y, s):
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.asarray(y).astype(bool)
    if y.all() or (~y).all():
        return {"roc_auc": None, "avg_precision": None}
    return {"roc_auc": round(float(roc_auc_score(y, s)), 4),
            "avg_precision": round(float(average_precision_score(y, s)), 4)}


def run_ml(feat: dict, rules: dict, g_val: pd.DataFrame, e_val: pd.DataFrame,
           g_test: pd.DataFrame, e_test: pd.DataFrame, bl_full, budget: float, seed: int = 0):
    """Fit on train, set the alert threshold on validation, grade on test.

    budget: fraction of validation (attack-free) groups allowed to alert; set to the rubric's own
    validation false-alarm rate so both methods spend the same budget.
    Returns (results dict, test group table with model scores).
    """
    tr = train_table_out_of_fold(feat["train"], rules)
    va = group_table(feat["val"], bl_full, rules, g_val)
    te = group_table(feat["test"], bl_full, rules, g_test)

    scorers = _fit_scorers(_transform(tr, FEATURES), _transform(tr, FEATURES_HYBRID), seed)
    Xva, Xva_h = _transform(va, FEATURES), _transform(va, FEATURES_HYBRID)
    Xte, Xte_h = _transform(te, FEATURES), _transform(te, FEATURES_HYBRID)

    y_g = te["evil_any"] > 0
    ev = e_test[["group_id", "evil"]].copy()
    results = {"alert_budget_val_groups": round(float(budget), 5),
               "train_groups": int(len(tr)), "val_groups": int(len(va)), "test_groups": int(len(te)),
               "features": FEATURES, "hybrid_extra_features": RUBRIC_FEATURES, "models": {}}
    test_scores = te[["evil_any"]].copy()
    for name, fn in scorers.items():
        sv, st = fn(Xva, Xva_h), fn(Xte, Xte_h)
        thr = float(np.quantile(sv, 1 - budget))
        alert = pd.Series(st >= thr, index=te.index)
        ev["alert"] = ev["group_id"].map(alert).fillna(False).astype(bool)
        results["models"][name] = {
            "group_level": metrics(y_g, alert), "event_level": metrics(ev["evil"] > 0, ev["alert"]),
            "validation_alert_rate": round(float((sv >= thr).mean()), 5),
            **_auc(y_g, st)}
        test_scores[name] = st
        test_scores[name + "_alert"] = alert
    results["rubric_score_threshold_free"] = _auc(y_g, te["score"])
    return results, test_scores.join(te[["n_events", "score"]])


def ml_report_lines(ml: dict, fm: dict) -> list:
    names = {"isolation_forest_features": "Isolation Forest (group features)",
             "local_outlier_factor_features": "Local Outlier Factor (group features)",
             "hybrid_isolation_forest_rubric_features": "Hybrid: Isolation Forest + rubric scores"}
    L = ["", "## Machine-learning models vs. the rubric (test split, action-group level)", "",
         f"All models are unsupervised, fit on attack-free training groups ({ml['train_groups']:,}), and "
         f"allowed the same false-alarm budget as the rubric on validation "
         f"({ml['alert_budget_val_groups']:.2%} of groups). Labels are used only for grading. "
         f"Test has only {ml['test_groups']:,} groups, so differences of a few points are noise.", "",
         "| Method | Precision | Recall | F1 | Alerts | ROC AUC | Avg precision |",
         "|---|---|---|---|---|---|---|"]
    m = fm["group_medium_plus"]
    ra = ml["rubric_score_threshold_free"]
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    L.append(f"| Rubric score >= 40 | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
             f"{m['alerts']} | {fmt(ra['roc_auc'])} | {fmt(ra['avg_precision'])} |")
    for k, v in ml["models"].items():
        g = v["group_level"]
        L.append(f"| {names[k]} | {g['precision']:.3f} | {g['recall']:.3f} | {g['f1']:.3f} | "
                 f"{g['alerts']} | {fmt(v['roc_auc'])} | {fmt(v['avg_precision'])} |")
    L += ["", "Event-level view (each event inherits its group's alert):", "",
          "| Method | Precision | Recall | F1 |", "|---|---|---|---|"]
    for k, v in ml["models"].items():
        e = v["event_level"]
        L.append(f"| {names[k]} | {e['precision']:.3f} | {e['recall']:.3f} | {e['f1']:.3f} |")
    return L

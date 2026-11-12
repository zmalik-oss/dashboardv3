"""Command line entry point.

    python -m triage describe  --data data/beth/labelled_train.csv
    python -m triage benchmark --data-dir data/beth
    python -m triage benchmark --data-dir data/sample          # synthetic demo data
    python -m triage benchmark --data-dir data/beth --ml       # also fit/grade the ML models
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .baseline import Baseline, fit_baseline
from .benchmark import (false_alarm_rates, framework_metrics, isolation_forest_baseline,
                        sus_label_baseline, threshold_sweep, write_report)
from .config import load_rules
from .export import _clean, export_dashboard
from .features import add_event_features
from .loader import describe, load_beth
from .ml import ml_report_lines, run_ml
from .scoring import score_events

# The Kaggle download names the splits *_training_data / *_validation_data / *_testing_data.
# The synthetic sample uses the shorter names, so both are accepted (first match wins).
SPLITS = {
    "train": ["labelled_training_data.csv", "labelled_train.csv"],
    "val": ["labelled_validation_data.csv", "labelled_validation.csv"],
    "test": ["labelled_testing_data.csv", "labelled_test.csv"],
}


def resolve_splits(data_dir: pathlib.Path) -> dict:
    found = {}
    for split, names in SPLITS.items():
        for n in names:
            if (data_dir / n).exists():
                found[split] = data_dir / n
                break
        else:
            found[split] = data_dir / names[0]   # reported as missing by the caller
    return found


def cmd_describe(a) -> int:
    df = load_beth(a.data, nrows=a.nrows)
    print(describe(df))
    return 0


def cmd_score(a) -> int:
    rules = load_rules(a.rules)
    bl = Baseline.load(a.baseline)
    df = add_event_features(load_beth(a.data, nrows=a.nrows), rules)
    groups, events = score_events(df, bl, rules)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    groups.drop(columns=["indicators", "reasons", "evidence"]).to_csv(out / "groups.csv", index=False)
    print(groups["tier"].value_counts().to_string())
    return 0


def cmd_benchmark(a) -> int:
    rules = load_rules(a.rules)
    d = pathlib.Path(a.data_dir)
    paths = resolve_splits(d)
    for k, p in paths.items():
        if not p.exists():
            print(f"missing {k} split: {p}\nRun scripts/download_beth.sh, or use --data-dir data/sample.",
                  file=sys.stderr)
            return 2
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    print("loading + feature extraction ...")
    feat = {k: add_event_features(load_beth(p, nrows=a.nrows), rules) for k, p in paths.items()}

    print("fitting baseline on train (labels not used) ...")
    bl = fit_baseline(feat["train"])
    bl.save(out / "baseline.json")

    print("scoring validation + test ...")
    g_val, e_val = score_events(feat["val"], bl, rules)
    g_test, e_test = score_events(feat["test"], bl, rules)

    fa = false_alarm_rates(g_val, e_val, rules)
    fm = framework_metrics(g_test, e_test, rules)
    print("training Isolation Forest baseline ...")
    iso = isolation_forest_baseline(feat["train"], feat["val"], feat["test"],
                                    target_alert_rate=fa["event_alert_rate_medium_plus"])
    results = {"framework_test": fm, "false_alarms_validation": fa,
               "baseline_sus": sus_label_baseline(e_test), "baseline_iforest": iso,
               "sweep_test": threshold_sweep(g_test)}
    ml_scores = None
    if a.ml:
        print("fitting ML models (out-of-fold baseline per training host) ...")
        budget = max(fa["group_alert_rate_medium_plus"], 0.005)
        results["ml"], ml_scores = run_ml(feat, rules, g_val, e_val, g_test, e_test, bl, budget)

    (out / "metrics.json").write_text(json.dumps(_clean(results), indent=2), encoding="utf-8")
    write_report(out / "report.md", {k: str(v.name) for k, v in paths.items()}, results, a.sample)
    if ml_scores is not None:
        with open(out / "report.md", "a", encoding="utf-8") as f:
            f.write("\n".join(ml_report_lines(results["ml"], fm)) + "\n")
        ml_scores.to_csv(out / "groups_test_ml.csv")
    cols = ["group_id", "hostName", "processId", "processName", "first_ts", "n_events", "behavior",
            "privilege", "resource", "supporting", "score", "tier", "sus_any", "evil_any", "disagreement"]
    g_test[cols].to_csv(out / "groups_test.csv", index=False)
    g_test[g_test["disagreement"] != ""][cols].to_csv(out / "review_queue.csv", index=False)

    is_sample = a.sample or "sample" in str(d)
    meta = {"source": "synthetic sample data (not BETH)" if is_sample else "BETH test split",
            "is_sample": bool(is_sample), "rules": "config/rules.yaml",
            "tiers": rules["tiers"], "gap_seconds": rules["grouping"]["gap_seconds"],
            "n_events": int(fm["workload"]["events"]), "n_groups": int(fm["workload"]["groups"]),
            "routine_min_count": rules["baseline"]["routine_min_count"],
            "network_burst_min_failures": rules["ioc"].get("network_burst_min_failures")}
    export_dashboard(g_test, results, meta, a.dashboard_dir)

    print(f"\nTest split: {fm['workload']['groups']:,} groups -> "
          f"low {fm['workload']['low']:,}, medium {fm['workload']['medium']:,}, high {fm['workload']['high']:,}")
    print(f"Group-level Medium+ vs evil: P={fm['group_medium_plus']['precision']:.3f} "
          f"R={fm['group_medium_plus']['recall']:.3f}")
    print(f"Outputs in {out}/ and {a.dashboard_dir}/results.js")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("describe", help="summarize a BETH CSV (event names, labels) to tune rules.yaml")
    d.add_argument("--data", required=True)
    d.add_argument("--nrows", type=int)
    d.set_defaults(fn=cmd_describe)

    s = sub.add_parser("score", help="score one CSV with a saved baseline")
    s.add_argument("--data", required=True)
    s.add_argument("--baseline", required=True)
    s.add_argument("--out", default="artifacts/scored")
    s.add_argument("--rules")
    s.add_argument("--nrows", type=int)
    s.set_defaults(fn=cmd_score)

    b = sub.add_parser("benchmark", help="fit on train, check false alarms on validation, evaluate on test")
    b.add_argument("--data-dir", default="data/beth")
    b.add_argument("--out", default="artifacts")
    b.add_argument("--dashboard-dir", default="dashboard")
    b.add_argument("--rules")
    b.add_argument("--nrows", type=int)
    b.add_argument("--ml", action="store_true", help="also fit and grade the ML models (slower)")
    b.add_argument("--sample", action="store_true", help="mark outputs as synthetic sample data")
    b.set_defaults(fn=cmd_benchmark)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
